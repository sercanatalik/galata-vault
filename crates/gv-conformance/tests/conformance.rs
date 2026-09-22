//! The suite against both targets, and proof that it is not vacuous: a
//! planted server fault fails the case that checks it, naming its id and
//! anchor.

use std::net::SocketAddr;
use std::sync::Arc;

use galata_vault::backend::{SqliteStore, StoreConfig};
use galata_vault::client::{Request, Response, Transport, TransportError};
use galata_vault::server::journal::FileJournal;
use galata_vault::server::{
    AppState, Core as ServerCore, Policy, ServerConfig, SystemClock, router,
};
use gv_conformance::{Target, Verdict, is_loopback, run};

fn assert_passes(report: &gv_conformance::Report, skipped: &[&str]) {
    let lines = report.lines().join("\n");
    assert_eq!(report.failed(), 0, "{lines}");
    for (case, verdict) in &report.results {
        let skip = matches!(verdict, Verdict::Skip(_));
        assert_eq!(skip, skipped.contains(&case.id), "{lines}");
    }
    assert_eq!(report.results.len(), 17, "{lines}");
}

#[cfg(feature = "embedded")]
#[test]
fn the_embedded_backend_conforms() {
    let dir = tempfile::tempdir().unwrap();
    let target = Target::embedded(&dir.path().join("data")).unwrap();
    assert_passes(&run(&target, None), &["C11", "C15"]);
}

/// A real HTTP server in-process on an ephemeral loopback port.
fn serve() -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    let store = Arc::new(SqliteStore::open(StoreConfig::new(&db)).unwrap());
    let journal = Arc::new(FileJournal::open(dir.path().join("journal")).unwrap());
    let core = ServerCore::open(store, journal, Policy::default(), Arc::new(SystemClock)).unwrap();
    let app = router(AppState::from_core(core, ServerConfig::for_database(&db)));
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
    (format!("http://{addr}"), dir)
}

#[test]
fn the_http_server_conforms() {
    let (url, _dir) = serve();
    let target = Target::http(&url).unwrap();
    assert_passes(&run(&target, None), &[]);
}

/// A server that answers a failed precondition with success.
struct IgnoresPreconditions(galata_vault::HttpTransport);

impl Transport for IgnoresPreconditions {
    fn send(&self, request: Request<'_>) -> Result<Response, TransportError> {
        let response = self.0.send(request)?;
        if response.status == 412 {
            return Ok(Response::new(200, br#"{"version":2}"#.to_vec()));
        }
        Ok(response)
    }
}

#[test]
fn a_planted_fault_fails_the_case_that_checks_it() {
    let (url, _dir) = serve();
    let http = galata_vault::ClientBuilder::new(&url)
        .build_transport()
        .unwrap();
    let target = Target::with_transport("planted", Arc::new(IgnoresPreconditions(http)), Some(url));
    let report = run(&target, Some(&["C03", "C04"]));
    assert_eq!(report.failed(), 1, "{:?}", report.lines());
    let line = report
        .lines()
        .into_iter()
        .find(|l| l.contains("FAIL"))
        .unwrap();
    assert!(
        line.starts_with("C04") && line.contains("http-api.md#4.2"),
        "{line}"
    );
}

#[cfg(not(feature = "embedded"))]
#[test]
fn without_its_feature_the_embedded_target_is_refused_by_name() {
    let refused = Target::embedded(std::path::Path::new("data"))
        .err()
        .unwrap();
    assert!(refused.contains("--features embedded"), "{refused}");
}

#[test]
fn every_case_cites_a_section_that_exists() {
    let spec = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/spec");
    for case in gv_conformance::cases() {
        let (file, id) = case.anchor.split_once('#').unwrap();
        let doc = std::fs::read_to_string(spec.join(file)).unwrap_or_default();
        assert!(
            doc.contains(&format!("<a id=\"{id}\"></a>")),
            "{} cites {}, which does not exist",
            case.id,
            case.anchor
        );
    }
}

#[test]
fn only_loopback_is_local() {
    for url in [
        "http://127.0.0.1:8750",
        "http://localhost:1",
        "http://[::1]:9/x",
    ] {
        assert!(is_loopback(url), "{url}");
    }
    for url in [
        "https://vault.example",
        "http://127.0.0.1.example:80",
        "http://10.0.0.1",
    ] {
        assert!(!is_loopback(url), "{url}");
    }
}

#[test]
fn the_binary_refuses_a_remote_server_before_sending_anything() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_gv-conformance"))
        .args(["--server", "https://vault.example"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Nothing was sent") && stderr.contains("--allow-remote"),
        "{stderr}"
    );
}
