//! What `ClientBuilder` promises about HTTP:
//! a private CA is trusted only when given, no proxy is taken from the
//! environment, and a redirect is refused rather than followed.
//!
//! The servers here are small std listeners (and rustls for TLS), so each
//! test controls exactly what is answered and counts what arrives.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use galata_vault_client::{ApiError, Auth, ClientBuilder, Method};

const OK: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";

/// Read a request head, up to the blank line. `None` if the peer never sent
/// one (a failed handshake, a closed connection).
fn read_head(stream: &mut impl Read) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return None,
        }
    }
    Some(String::from_utf8_lossy(&head).into_owned())
}

/// A plain HTTP server answering every request with `response`. Returns its
/// address and how many connections it accepted.
fn serve(response: String) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            seen.fetch_add(1, Ordering::SeqCst);
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            if read_head(&mut stream).is_some() {
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        }
    });
    (addr, count)
}

// ------------------------------------------------------------ private CA

/// A TLS server with the test certificate (tests/certs). Returns its port,
/// how many connections it accepted, and how many requests it served.
fn serve_tls() -> (u16, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let chain = vec![CertificateDer::from(
        include_bytes!("certs/server.der").to_vec(),
    )];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        include_bytes!("certs/server.key.der").to_vec(),
    ));
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (accepted, served) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let (a, s) = (accepted.clone(), served.clone());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(tcp) = stream else { continue };
            a.fetch_add(1, Ordering::SeqCst);
            tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let conn = rustls::ServerConnection::new(config.clone()).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, tcp);
            if read_head(&mut tls).is_some() {
                s.fetch_add(1, Ordering::SeqCst);
                let _ = tls.write_all(OK.as_bytes());
                tls.conn.send_close_notify();
                let _ = tls.flush();
            }
        }
    });
    (port, accepted, served)
}

#[test]
fn a_private_ca_is_trusted_only_when_given() {
    let (port, accepted, served) = serve_tls();
    let url = format!("https://127.0.0.1:{port}");
    let ca = include_bytes!("certs/ca.der").to_vec();

    let trusting = ClientBuilder::new(&url)
        .root_certificates(vec![ca])
        .build()
        .unwrap();
    let reply = trusting
        .call(Method::Get, "/v1/vault", None, Auth::None, None)
        .unwrap();
    assert_eq!((reply.status, reply.body.as_slice()), (200, &b"{}"[..]));
    assert_eq!(served.load(Ordering::SeqCst), 1);

    // The bundled Mozilla roots do not include the test CA.
    let default = ClientBuilder::new(&url).build().unwrap();
    let err = default
        .call(Method::Get, "/v1/vault", None, Auth::None, None)
        .unwrap_err();
    assert!(matches!(err, ApiError::Transport(_)), "{err:?}");
    assert_eq!(err.stable_code(), "unreachable");
    // The handshake was attempted and failed: no request was served.
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
    assert_eq!(served.load(Ordering::SeqCst), 1);
}

// ------------------------------------------------------------ no env proxy

const CHILD: &str = "GV_CLIENT_CHILD";
const PROXY_VARS: [&str; 6] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
];

fn is_child(role: &str) -> bool {
    std::env::var(CHILD).is_ok_and(|r| r == role)
}

/// Run one test of this binary in a child process with `envs` set (the
/// workspace forbids the `unsafe` that `set_var` needs).
fn run_child(test: &str, envs: &[(&str, &str)]) {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", test, "--test-threads=1", "--nocapture"]);
    for var in PROXY_VARS.iter().chain(&["NO_PROXY", "no_proxy"]) {
        cmd.env_remove(var);
    }
    cmd.envs(envs.iter().copied());
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{test}\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn child_proxy() {
    if !is_child("proxy") {
        return;
    }
    let proxy = std::env::var("HTTPS_PROXY").unwrap();
    let (addr, direct) = serve(OK.to_owned());
    let url = format!("http://{addr}");
    let get =
        |api: &galata_vault_client::Api| api.call(Method::Get, "/v1/vault", None, Auth::None, None);

    // No proxy given: straight to the server, whatever the environment says.
    let reply = get(&ClientBuilder::new(&url).build().unwrap()).unwrap();
    assert_eq!(reply.status, 200);
    assert_eq!(direct.load(Ordering::SeqCst), 1);

    // Control: the environment is live. A default ureq agent follows it to
    // the proxy (which answers 502), so the server sees nothing.
    let status = match ureq::get(format!("{url}/v1/vault")).call() {
        Ok(r) => r.status().as_u16(),
        Err(ureq::Error::StatusCode(s)) => s,
        Err(_) => 0,
    };
    assert_ne!(status, 200, "a default agent should have used the proxy");
    assert_eq!(direct.load(Ordering::SeqCst), 1);

    // Control: an explicit proxy is used.
    let via = get(&ClientBuilder::new(&url)
        .proxy(Some(&proxy))
        .build()
        .unwrap());
    assert!(via.is_err(), "the proxy answers 502, never the server");
    assert_eq!(direct.load(Ordering::SeqCst), 1);
}

#[test]
fn no_proxy_is_taken_from_the_environment() {
    let (proxy, through_proxy) = serve(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
    );
    let proxy = format!("http://{proxy}");
    let mut envs: Vec<(&str, &str)> = PROXY_VARS.iter().map(|v| (*v, proxy.as_str())).collect();
    envs.push((CHILD, "proxy"));
    run_child("child_proxy", &envs);
    // Exactly the two controls went through the proxy; the builder without
    // a proxy did not.
    assert_eq!(through_proxy.load(Ordering::SeqCst), 2);
}

// ------------------------------------------------------------ redirects

#[test]
fn a_redirect_is_refused_not_followed() {
    let (target, reached) = serve(OK.to_owned());
    let (redirecting, _) = serve(format!(
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{target}/v1/vault\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    ));
    let api = ClientBuilder::new(&format!("http://{redirecting}"))
        .build()
        .unwrap();
    let err = api
        .call(Method::Get, "/v1/vault", None, Auth::None, None)
        .unwrap_err();
    match &err {
        ApiError::Transport(t) => assert!(t.message().contains("redirect"), "{t}"),
        other => panic!("expected a transport error, got {other:?}"),
    }
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(reached.load(Ordering::SeqCst), 0, "the target was reached");
    // Nothing reached the target by any other route either.
    assert!(TcpStream::connect(&target).is_ok());
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(reached.load(Ordering::SeqCst), 1, "the counter works");
}
