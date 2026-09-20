//! The CLI as a library (the cli-library spec): the example product binary,
//! which flattens the vault commands beside its own, runs with its own home
//! (`ACME_HOME`), its own words (`acme: …`), a scripted prompter and a
//! capturing output. Nothing reaches the process's own stdout or stderr.
//!
//! The run happens in a child process: the workspace forbids the `unsafe`
//! that setting `ACME_HOME` in this process would need.

#[path = "../examples/branded.rs"]
#[allow(dead_code)]
mod branded;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use clap::Parser;
use galata_vault_cli::{CapturedOutput, Context, ScriptedPrompter};
use galata_vault_server::journal::FileJournal;
use galata_vault_server::{AppState, ServerConfig, SystemClock, router};
use galata_vault_store::{SqliteStore, StoreConfig};

const CHILD: &str = "GV_LIBRARY_CHILD";

fn start() -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    let store = Arc::new(SqliteStore::open(StoreConfig::new(&db)).unwrap());
    let config = ServerConfig::for_database(&db);
    let journal = Arc::new(FileJournal::open(dir.path().join("journal")).unwrap());
    let state = AppState::new(store, journal, config, Arc::new(SystemClock)).unwrap();
    let app = router(state);
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

fn acme(ctx: &mut Context, args: &[&str]) -> anyhow::Result<()> {
    let cli = branded::Acme::try_parse_from(std::iter::once("acme").chain(args.iter().copied()))?;
    branded::dispatch(ctx, cli)
}

/// The child: `acme init`, `env add`, `set`, `get` and the product's own
/// `deploy`, all through one context whose home comes from `ACME_HOME`.
#[test]
fn child_branded() {
    if std::env::var(CHILD).as_deref() != Ok("branded") {
        return;
    }
    let server = std::env::var("ACME_TEST_SERVER").unwrap();
    let work = PathBuf::from(std::env::var("ACME_TEST_WORK").unwrap());
    let kit = work.join("acme.gvkit");
    let output = Arc::new(CapturedOutput::new());
    let mut ctx = Context::builder(branded::ACME)
        .output(output.clone())
        .prompter(
            ScriptedPrompter::new()
                .line("saved")
                .stdin(b"s3cret".to_vec()),
        )
        .build();

    let kit_arg = kit.to_str().unwrap();
    acme(
        &mut ctx,
        &["init", "acme", "--server", &server, "--kit", kit_arg],
    )
    .unwrap();
    acme(&mut ctx, &["env", "add", "acme/prod"]).unwrap();
    acme(&mut ctx, &["set", "DB", "--env", "acme/prod"]).unwrap();
    acme(&mut ctx, &["get", "DB", "--env", "acme/prod"]).unwrap();
    acme(&mut ctx, &["deploy", "prod"]).unwrap();
    // A typo is refused in the product's own words.
    let e = acme(&mut ctx, &["get", "DB", "--env", "acme/prdo"]).unwrap_err();
    let refused = galata_vault_cli::render_error(&e, &branded::ACME);
    assert!(
        refused.contains("did you mean acme/prod?") && refused.contains("`acme env ls acme`"),
        "{refused}"
    );

    assert_eq!(output.stdout_text(), "s3cret");
    let err = output.stderr_text();
    for line in err.lines().filter(|l| !l.is_empty()) {
        assert!(
            line.starts_with("acme: ") || line.starts_with("Type \"saved\""),
            "{line:?} in\n{err}"
        );
    }
    for said in [
        "acme: wrote the recovery kit for acme",
        "acme: created project acme on",
        "acme: created acme/prod",
        "acme: set DB in acme/prod (version 1)",
        "acme: deploying to prod",
    ] {
        assert!(err.contains(said), "{said:?} not in\n{err}");
    }
    assert!(
        std::fs::read_to_string(&kit)
            .unwrap()
            .starts_with("# acme-cloud recovery kit (v1)")
    );
    let home = PathBuf::from(std::env::var("ACME_HOME").unwrap());
    let config = std::fs::read_to_string(home.join("config.toml")).unwrap();
    assert!(config.contains("[projects.acme]") && !config.contains("gvk1_"));
    let creds = std::fs::read_to_string(home.join("credentials.toml")).unwrap();
    assert!(
        creds.contains("node:acme"),
        "the key lives in acme's own home"
    );
}

#[test]
fn a_branded_binary_keeps_its_own_home_words_and_terminal() {
    let (server, _data) = start();
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "--exact",
        "child_branded",
        "--test-threads=1",
        "--nocapture",
    ]);
    for var in [
        "GV_HOME",
        "GV_ENV",
        "GV_TOKEN",
        "GV_SERVER",
        "ACME_ENV",
        "ACME_TOKEN",
    ] {
        cmd.env_remove(var);
    }
    let out = cmd
        .env(CHILD, "branded")
        .env("ACME_HOME", home.path())
        .env("ACME_CREDENTIAL_STORE", "file")
        .env("ACME_TEST_SERVER", &server)
        .env("ACME_TEST_WORK", work.path())
        .current_dir(work.path())
        .output()
        .unwrap();
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.status.success(), "{stdout}{stderr}");
    // Everything the commands said went to the captured output: the
    // process's own streams carry only the test harness's lines.
    assert!(stderr.is_empty(), "stderr: {stderr}");
    for line in stdout.lines() {
        assert!(
            line.is_empty() || line.starts_with("running ") || line.starts_with("test "),
            "unexpected output: {line:?}"
        );
    }
    assert!(home.path().join("config.toml").exists());
    assert!(home.path().join("state.toml").exists());
}

/// The vault commands flatten beside the product's own, and the whole tree
/// parses with the product's name.
#[test]
fn the_command_tree_flattens() {
    use clap::CommandFactory;
    let cmd = branded::Acme::command();
    assert_eq!(cmd.get_name(), "acme");
    let names: Vec<&str> = cmd.get_subcommands().map(|c| c.get_name()).collect();
    for want in ["init", "env", "set", "get", "token", "rekey", "deploy"] {
        assert!(names.contains(&want), "{want} missing from {names:?}");
    }
    let gv = galata_vault_cli::Cli::command_for(&galata_vault_cli::Branding::GV);
    assert_eq!(gv.get_name(), "gv");
}

/// The review-status statement ends `gv --help`, word for word, until an
/// external review is published: the review status is stated wherever
/// users meet the package.
#[test]
fn help_ends_with_the_review_status() {
    let flat = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut gv = galata_vault_cli::Cli::command_for(&galata_vault_cli::Branding::GV);
    let help = gv.render_long_help().to_string();
    assert!(flat(&help).contains(galata_vault::REVIEW_STATUS), "{help}");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_gv"))
        .arg("--help")
        .output()
        .expect("gv --help runs");
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(flat(&help).contains(galata_vault::REVIEW_STATUS), "{help}");
    assert!(
        flat(&help).contains("has not been independently audited"),
        "{help}"
    );
}
