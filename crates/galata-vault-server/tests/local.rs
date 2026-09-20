//! `gv-server local` as a real process: first start, a vault surviving a
//! SIGTERM restart, the durability notice, the refusals, and service
//! definitions that start nothing.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use galata_vault_keys::{FullBundle, NodeKey, OwnerKeys, seal_owner_bundle};
use galata_vault_proto::api::{Capabilities, CreateVaultRequest, VaultStatus};
use galata_vault_proto::ids::Hash32;
use galata_vault_proto::sig::SignedRequest;
use galata_vault_server_core::data_dir::DataDir;
use galata_vault_server_core::{CanonicalRequest, Core, FileJournal, Policy, SystemClock};
use galata_vault_store::{SqliteStore, StoreConfig};

const BIN: &str = env!("CARGO_BIN_EXE_gv-server");

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let nl = b.windows(2).position(|w| w == b"\r\n").unwrap();
        let size =
            usize::from_str_radix(std::str::from_utf8(&b[..nl]).unwrap().trim(), 16).unwrap();
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&b[nl + 2..nl + 2 + size]);
        b = &b[nl + 2 + size + 2..];
    }
}

/// One HTTP/1.1 exchange over a fresh connection: status and body.
fn http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> (u16, Vec<u8>) {
    let (status, _, body) = exchange(port, method, path, headers, body);
    (status, body)
}

/// As [`http`], also returning the response head, lower-cased.
fn exchange(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> (u16, String, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    let rest = &raw[split + 4..];
    let body = if head.contains("transfer-encoding: chunked") {
        dechunk(rest)
    } else {
        rest.to_vec()
    };
    (status, head, body)
}

fn start(dir: &Path, port: u16, log: &Path) -> Child {
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .unwrap();
    Command::new(BIN)
        .args([
            "local",
            "--data-dir",
            dir.to_str().unwrap(),
            "--port",
            &port.to_string(),
        ])
        .env("GV_LOG", "info")
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .unwrap()
}

fn wait_healthy(port: u16, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("gv-server local exited early: {status}");
        }
        if TcpStream::connect(("127.0.0.1", port)).is_ok()
            && http(port, "GET", "/healthz", &[], b"").0 == 200
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("gv-server local did not become healthy");
}

/// SIGTERM, as launchd and systemd stop a service: a clean exit.
fn stop(mut child: Child) {
    let sent = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(sent.success());
    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "a SIGTERM stops the server cleanly: {status}"
    );
}

/// A `GV-Sig v=1` owner signature for a request with no precondition.
fn sign(owner: &OwnerKeys, method: &str, path: &str, body: &[u8]) -> String {
    owner
        .sign_request(&SignedRequest::new(method, path, body), now())
        .to_header_value()
}

fn create_vault(port: u16) -> OwnerKeys {
    let owner = NodeKey::generate().owner();
    let json = ("content-type", "application/json".to_owned());
    let (code, body) = http(port, "GET", "/v1/capabilities", &[], b"");
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let caps: Capabilities = serde_json::from_slice(&body).unwrap();
    assert!(
        caps.proof_of_work.is_none(),
        "local mode asks for no proof of work"
    );
    let (code, body) = http(
        port,
        "POST",
        "/v1/challenges",
        std::slice::from_ref(&json),
        br#"{"purpose":"create_vault"}"#,
    );
    assert_eq!(code, 404, "there is no challenge to ask for");
    let _ = body;
    let full = FullBundle::generate(1);
    let descriptor = full.descriptor(owner.vault_id(), Hash32([0; 32]), now());
    let request = CreateVaultRequest::new(
        owner.vault_id(),
        owner.sign_pub(),
        owner.box_pub(),
        owner.sign_descriptor(&descriptor),
        seal_owner_bundle(&owner, &full).unwrap(),
    );
    let body = serde_json::to_vec(&request).unwrap();
    let sig = sign(&owner, "POST", "/v1/vaults", &body);
    let (code, reply) = http(
        port,
        "POST",
        "/v1/vaults",
        &[("authorization", sig), json],
        &body,
    );
    assert_eq!(code, 201, "{}", String::from_utf8_lossy(&reply));
    owner
}

fn vault_status(port: u16, owner: &OwnerKeys) -> (u16, Vec<u8>) {
    let sig = sign(owner, "GET", "/v1/vault", b"");
    http(port, "GET", "/v1/vault", &[("authorization", sig)], b"")
}

#[test]
fn first_start_restart_and_the_durability_notice() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("share/galata-vault");
    let log = tmp.path().join("server.log");
    let port = free_port();

    let mut child = start(&dir, port, &log);
    wait_healthy(port, &mut child);
    assert_eq!(mode(&dir), 0o700);
    assert!(dir.join("vault.db").exists());
    assert!(dir.join("journal-root/journal").is_dir());
    let owner = create_vault(port);
    stop(child);

    let mut child = start(&dir, port, &log);
    wait_healthy(port, &mut child);
    let (code, body) = vault_status(port, &owner);
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let status: VaultStatus = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        status.vault_id,
        owner.vault_id(),
        "the vault survived the restart"
    );
    stop(child);

    let text = fs::read_to_string(&log).unwrap();
    assert!(text.contains("single-machine durability"), "{text}");
    assert!(
        text.contains(dir.to_str().unwrap()),
        "the log names the data directory"
    );
}

#[test]
fn refusals_and_service_definitions() {
    let tmp = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| Command::new(BIN).arg("local").args(args).output().unwrap();

    let open = tmp.path().join("open");
    fs::create_dir(&open).unwrap();
    fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
    let out = run(&[
        "--data-dir",
        open.to_str().unwrap(),
        "--port",
        &free_port().to_string(),
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && err.contains("0755") && err.contains("0700"),
        "{err}"
    );

    let never = tmp.path().join("never");
    let out = run(&[
        "--data-dir",
        never.to_str().unwrap(),
        "--listen",
        "0.0.0.0:8750",
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && err.contains("loopback only"),
        "{err}"
    );
    assert!(!never.exists(), "nothing is created for a refused address");

    let fresh = tmp.path().join("fresh");
    let out = run(&[
        "--data-dir",
        fresh.to_str().unwrap(),
        "--port",
        "9000",
        "--print-service",
        "launchd",
    ]);
    assert!(out.status.success());
    let plist = String::from_utf8(out.stdout).unwrap();
    let bin = fs::canonicalize(BIN).unwrap();
    assert!(
        plist.contains(&format!("<string>{}</string>", bin.display()))
            || plist.contains(&format!("<string>{BIN}</string>")),
        "{plist}"
    );
    assert!(
        plist.contains("<string>local</string>")
            && plist.contains("<string>127.0.0.1:9000</string>")
    );
    assert!(plist.contains(fresh.to_str().unwrap()));
    assert!(
        !fresh.exists(),
        "printing a service definition creates nothing"
    );

    let out = run(&[
        "--data-dir",
        fresh.to_str().unwrap(),
        "--print-service",
        "systemd",
    ]);
    let unit = String::from_utf8(out.stdout).unwrap();
    assert!(
        unit.contains("ExecStart=") && unit.contains("local --data-dir"),
        "{unit}"
    );
    let _ = File::open(tmp.path()).unwrap();
}

fn signed_status(port: u16, owner: &OwnerKeys) -> (String, VaultStatus) {
    let sig = sign(owner, "GET", "/v1/vault", b"");
    let (code, head, body) = exchange(port, "GET", "/v1/vault", &[("authorization", sig)], b"");
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    (head, serde_json::from_slice(&body).unwrap())
}

/// Local mode announces no expiry, and the flag that once turned one on is
/// refused by name, creating nothing.
#[test]
fn local_mode_announces_no_expiry_and_refuses_the_removed_flags() {
    let tmp = tempfile::tempdir().unwrap();
    let log = tmp.path().join("server.log");

    let (dir, port) = (tmp.path().join("default"), free_port());
    let mut child = start(&dir, port, &log);
    wait_healthy(port, &mut child);
    let owner = create_vault(port);
    let (head, status) = signed_status(port, &owner);
    assert!(!head.contains("x-gv-expires-at"), "{head}");
    assert_eq!(status.expires_at, None);
    stop(child);
    let text = fs::read_to_string(&log).unwrap();
    assert!(text.contains("never expire"), "{text}");

    for flag in ["--idle-expiry-days", "--pow-difficulty"] {
        let refused = tmp.path().join(format!("refused{flag}"));
        let out = Command::new(BIN)
            .args([
                "local",
                "--data-dir",
                refused.to_str().unwrap(),
                "--port",
                &free_port().to_string(),
                flag,
                "30",
            ])
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success() && err.contains(flag) && err.contains("no longer supported"),
            "{err}"
        );
        assert!(!err.contains("feature"), "{err}");
        assert!(!refused.exists(), "nothing is created for a refused flag");
    }
}

/// One opener per data directory: a second `gv-server local` on it is
/// refused with `data_dir_in_use`, changes nothing, and the first keeps
/// serving.
#[test]
fn a_data_directory_has_one_server() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("data");
    let log = tmp.path().join("server.log");
    let port = free_port();
    let mut child = start(&dir, port, &log);
    wait_healthy(port, &mut child);
    let owner = create_vault(port);
    assert!(
        dir.join("lock").exists(),
        "the lock lives in the data directory"
    );

    let out = Command::new(BIN)
        .args([
            "local",
            "--data-dir",
            dir.to_str().unwrap(),
            "--port",
            &free_port().to_string(),
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && err.contains("data_dir_in_use"),
        "{err}"
    );
    let (code, body) = vault_status(port, &owner);
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    stop(child);

    // Stopped, it lets the next opener in: here, what the SDK's embedded
    // backend does (the lock, then the core over the same files).
    {
        let data = DataDir::open(&dir).expect("released when the server stopped");
        let store = Arc::new(SqliteStore::open(StoreConfig::new(data.database())).unwrap());
        let journal = Arc::new(FileJournal::open(data.journal_root()).unwrap());
        let core = Core::open(store, journal, Policy::default(), Arc::new(SystemClock)).unwrap();
        let authorization = sign(&owner, "GET", "/v1/vault", b"");
        let answer = core.call(CanonicalRequest {
            method: "GET",
            path_and_query: "/v1/vault",
            authorization: Some(&authorization),
            if_match: None,
            if_none_match: None,
            body: b"",
        });
        assert_eq!(answer.status, 200, "{answer:?}");
        let status: VaultStatus = serde_json::from_slice(&answer.body).unwrap();
        assert_eq!(status.vault_id, owner.vault_id());
    }

    // And a local server after it.
    let port = free_port();
    let mut child = start(&dir, port, &log);
    wait_healthy(port, &mut child);
    assert_eq!(vault_status(port, &owner).0, 200);
    stop(child);
}
