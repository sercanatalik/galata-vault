//! The transport seam carries the canonical request unchanged: what `Api`
//! hands a transport is exactly what reaches
//! the server, byte for byte, and a recording transport sees the same
//! request without opening a socket.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use galata_vault_client::{
    Api, ApiError, Auth, ClientBuilder, Method, Pre, Recorded, RecordingTransport, Response,
};
use galata_vault_keys::{FullBundle, NodeKey, seal_owner_bundle};
use galata_vault_proto::api::CreateVaultRequest;
use galata_vault_proto::children::ChildrenRecord;
use galata_vault_proto::ids::Hash32;
use galata_vault_proto::sig::{SigActor, SigParams};
use galata_vault_server::journal::FileJournal;
use galata_vault_server::{AppState, ServerConfig, SystemClock, router};
use galata_vault_store::{SqliteStore, StoreConfig};

/// One request as it arrived on the wire, or as the transport was handed it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Wire {
    method: String,
    path_and_query: String,
    authorization: Option<String>,
    if_match: Option<String>,
    if_none_match: Option<String>,
    body: Vec<u8>,
}

impl From<&Recorded> for Wire {
    fn from(r: &Recorded) -> Wire {
        Wire {
            method: r.method.as_str().to_owned(),
            path_and_query: r.path_and_query.clone(),
            authorization: r.authorization.clone(),
            if_match: r.if_match.clone(),
            if_none_match: r.if_none_match.clone(),
            body: r.body.clone().unwrap_or_default(),
        }
    }
}

struct Server {
    url: String,
    seen: Arc<Mutex<Vec<Wire>>>,
    _dir: tempfile::TempDir,
}

/// A real gv-server on loopback, behind a layer that records every request
/// as it arrived.
fn start() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    let store = Arc::new(SqliteStore::open(StoreConfig::new(&db)).unwrap());
    let config = ServerConfig::for_database(&db);
    let journal = Arc::new(FileJournal::open(dir.path().join("journal")).unwrap());
    let state = AppState::new(store, journal, config, Arc::new(SystemClock)).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let app = router(state).layer(axum::middleware::from_fn(
        move |req: Request, next: Next| {
            let log = log.clone();
            async move {
                let (parts, body) = req.into_parts();
                let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
                let header = |name: &str| {
                    parts
                        .headers
                        .get(name)
                        .map(|v| v.to_str().unwrap().to_owned())
                };
                log.lock().unwrap().push(Wire {
                    method: parts.method.as_str().to_owned(),
                    path_and_query: parts
                        .uri
                        .path_and_query()
                        .map(|p| p.as_str().to_owned())
                        .unwrap(),
                    authorization: header("authorization"),
                    if_match: header("if-match"),
                    if_none_match: header("if-none-match"),
                    body: bytes.to_vec(),
                });
                next.run(Request::from_parts(parts, Body::from(bytes)))
                    .await
            }
        },
    ));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
    });
    Server {
        url: format!("http://{addr}"),
        seen,
        _dir: dir,
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
fn an_owner_operation_reaches_the_server_exactly_as_canonicalised() {
    let server = start();
    let http = ClientBuilder::new(&server.url).build_transport().unwrap();
    let recorder = Arc::new(RecordingTransport::forwarding(Arc::new(http)));
    let api = Api::shared(recorder.clone());

    // Create a vault (the unauthenticated capabilities, which ask for no
    // challenge, then a signed POST), read its status (a signed GET) and
    // write its children record (a signed PUT under `If-None-Match: *`).
    let key = NodeKey::generate();
    let owner = key.owner();
    let caps = api
        .capabilities()
        .unwrap()
        .expect("the server has capabilities");
    assert_eq!(caps.proof_of_work, None, "a default server asks for none");
    let full = FullBundle::generate(1);
    let descriptor = full.descriptor(owner.vault_id(), Hash32([0; 32]), now());
    let request = CreateVaultRequest::new(
        owner.vault_id(),
        owner.sign_pub(),
        owner.box_pub(),
        owner.sign_descriptor(&descriptor),
        seal_owner_bundle(&owner, &full).unwrap(),
    );
    api.create_vault(&owner, &request).unwrap();
    let status = api.status(Auth::Owner(&owner)).unwrap();
    assert_eq!(status.value.vault_id, owner.vault_id());
    api.children_put(
        &owner,
        &owner.seal_children(1, &ChildrenRecord::new()).unwrap(),
        Pre::Create,
    )
    .unwrap();

    let canonical = recorder.requests();
    let wire = server.seen.lock().unwrap().clone();
    assert_eq!(canonical.len(), 4, "{canonical:?}");
    assert_eq!(wire.len(), canonical.len(), "{wire:?}");
    for (c, w) in canonical.iter().zip(&wire) {
        assert_eq!(&Wire::from(c), w, "the transport changed the request");
    }

    // The requests are the ones the protocol expects, signed where it says.
    let methods: Vec<_> = canonical
        .iter()
        .map(|r| (r.method, r.path_and_query.as_str()))
        .collect();
    assert_eq!(
        methods,
        [
            (Method::Get, "/v1/capabilities"),
            (Method::Post, "/v1/vaults"),
            (Method::Get, "/v1/vault"),
            (Method::Put, "/v1/vault/children"),
        ]
    );
    assert!(canonical[0].authorization.is_none());
    for r in &canonical[1..] {
        let sig = SigParams::parse(r.authorization.as_deref().unwrap()).unwrap();
        assert_eq!(
            (sig.actor, sig.vault_id),
            (SigActor::Owner, owner.vault_id())
        );
    }
    // A GET carries no body at all; the wire saw an empty one.
    assert_eq!(canonical[2].body, None);
    assert!(wire[2].body.is_empty());
    // The precondition went out exactly as signed.
    assert_eq!(
        (
            canonical[3].if_match.as_deref(),
            canonical[3].if_none_match.as_deref()
        ),
        (None, Some("*"))
    );
    assert_eq!(wire[3].if_none_match.as_deref(), Some("*"));
}

#[test]
fn a_recording_transport_captures_and_replays_without_a_socket() {
    let recorder = Arc::new(RecordingTransport::new());
    recorder.replay(Response::new(
        404,
        br#"{"error":"not_found","message":"no such vault"}"#.to_vec(),
    ));
    let api = Api::shared(recorder.clone());
    let owner = NodeKey::generate().owner();

    let err = api.status(Auth::Owner(&owner)).unwrap_err();
    match &err {
        ApiError::Refused {
            status, message, ..
        } => assert_eq!((*status, message.as_str()), (404, "no such vault")),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(err.stable_code(), "not_found");

    let requests = recorder.requests();
    assert_eq!(requests.len(), 1);
    let r = &requests[0];
    assert_eq!(
        (r.method, r.path_and_query.as_str()),
        (Method::Get, "/v1/vault")
    );
    assert_eq!((r.body.as_ref(), r.if_match.as_ref()), (None, None));
    let header = r.authorization.as_deref().unwrap();
    assert!(header.starts_with("GV-Sig v=1,actor=owner,"), "{header}");
    let sig = SigParams::parse(header).unwrap();
    assert_eq!(sig.vault_id, owner.vault_id());
    // Debug output never shows the signature header.
    assert!(!format!("{r:?}").contains("GV-Sig"));

    // With nothing left to replay, the recorder answers 404 on its own.
    let err = api.status(Auth::None).unwrap_err();
    assert_eq!(err.stable_code(), "not_found");
    assert_eq!(recorder.requests()[1].authorization, None);
}
