//! `gv ui`: the vault in a browser, served by this process on loopback.
//!
//! The keys never leave `gv`. The page gets names and metadata, a value only
//! when the user reveals it, and never a key or a token. Anything that mints,
//! revokes, rotates or deletes waits for `y` in the terminal that started
//! `gv ui`: script injected into the page can ask, but it cannot answer.
//!
//! One thread owns everything: the owner API and its key store, the browser
//! session, the pending confirmation and the clipboard timers. It takes HTTP
//! requests, terminal lines and timer ticks in turn. Every vault operation is
//! the SDK's owner API.

mod app;
mod clip;
mod pages;
mod web;

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context as _, bail};
use galata_vault::owner::Owner;
use galata_vault::{FileStateStore, KeyStore};

use crate::branding::Branding;
use crate::config::Home;
use crate::context::{CliEvents, Context, Output, StdOutput};
use crate::keystore::{CredentialsFile, LazyKeyStore};
use crate::style::{Paint, Role};

pub use clip::Clipboard;

/// How long things last. The defaults are the spec's; tests shorten them.
#[derive(Debug, Clone, Copy)]
pub struct Timings {
    /// An unused link stops working after this.
    pub code_lapse: Duration,
    /// A session with no activity ends after this.
    pub idle: Duration,
    /// A confirmation nobody answers is cancelled after this.
    pub confirm_lapse: Duration,
    /// A copied value is cleared from the clipboard after this.
    pub clipboard_clear: Duration,
    /// The page hides a revealed value after this.
    pub reveal: Duration,
}

impl Default for Timings {
    fn default() -> Timings {
        Timings {
            code_lapse: Duration::from_secs(60),
            idle: Duration::from_secs(15 * 60),
            confirm_lapse: Duration::from_secs(120),
            clipboard_clear: Duration::from_secs(30),
            reveal: Duration::from_secs(10),
        }
    }
}

/// How [`start`] runs the UI.
pub struct UiOptions {
    /// The configuration home; `None` finds it as every command does.
    pub home: Option<PathBuf>,
    /// Keep keys in the 0600 credentials file instead of the keychain.
    pub file_store: bool,
    /// How values are copied to the clipboard.
    pub clipboard: Clipboard,
    /// How long things last.
    pub timings: Timings,
}

impl Default for UiOptions {
    fn default() -> UiOptions {
        UiOptions {
            home: None,
            file_store: false,
            clipboard: Clipboard::Detect,
            timings: Timings::default(),
        }
    }
}

/// A running `gv ui`. Dropping it stops the UI.
pub struct UiHandle {
    /// `http://127.0.0.1:<port>`.
    pub origin: String,
    /// Lines typed at the terminal; an empty line is Enter.
    pub terminal: mpsc::Sender<String>,
    /// Lines `gv ui` prints to its terminal.
    pub feed: mpsc::Receiver<String>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl UiHandle {
    /// End the session, clear the clipboard if it still holds a value this
    /// UI put there, and wait for the loop to finish.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for UiHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The owner the UI acts through: its events show warnings and nothing else
/// (the page shows expiry itself, and progress is its own feed).
fn ui_owner(owner: Owner, output: Arc<dyn Output>, branding: Branding) -> Owner {
    owner.with_events(Arc::new(CliEvents::new(output, branding, false, false)))
}

/// Start `gv ui` on its own thread, over the home in `opts`. The command
/// wires the terminal and the feed to stdin and stdout; tests drive them
/// directly.
pub fn start(opts: UiOptions) -> anyhow::Result<UiHandle> {
    let branding = Branding::GV;
    let home = match opts.home {
        Some(dir) => Home { dir },
        None => Home::locate(&branding)?,
    };
    let output: Arc<dyn Output> = Arc::new(StdOutput);
    let keys: Arc<dyn KeyStore> = if opts.file_store {
        Arc::new(CredentialsFile::new(home.credentials_path()))
    } else {
        Arc::new(LazyKeyStore::new(home.clone(), branding, output.clone()))
    };
    let owner = Owner::open(keys, Arc::new(FileStateStore::new(&home.dir)))?;
    start_owner(
        ui_owner(owner, output, branding),
        branding,
        opts.clipboard,
        opts.timings,
    )
}

fn start_owner(
    owner: Owner,
    branding: Branding,
    clipboard: Clipboard,
    timings: Timings,
) -> anyhow::Result<UiHandle> {
    let stop = Arc::new(AtomicBool::new(false));
    let (term_tx, term_rx) = mpsc::channel();
    let (feed_tx, feed_rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let flag = stop.clone();
    // The loop is built on its own thread and never leaves it: the owner and
    // its key store are not shared, only the origin comes back.
    let thread =
        std::thread::Builder::new()
            .name("gv-ui".into())
            .spawn(move || {
                match app::App::new(owner, branding, clipboard, timings, term_rx, feed_tx, flag) {
                    Ok(app) => {
                        let _ = ready_tx.send(Ok(app.origin().to_owned()));
                        app.run();
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                    }
                }
            })?;
    let origin = ready_rx
        .recv()
        .with_context(|| format!("{} ui stopped while starting", branding.bin_name))??;
    Ok(UiHandle {
        origin,
        terminal: term_tx,
        feed: feed_rx,
        stop,
        thread: Some(thread),
    })
}

/// `gv ui`, over the command's context: its key store, state store and
/// output.
pub fn run_cli(ctx: &Context, open_browser: bool) -> anyhow::Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!(
            "{} ui needs a terminal on stdin and stdout: that is where you confirm tokens, \
             revocations and deletions",
            ctx.branding().bin_name
        );
    }
    let owner = ui_owner(ctx.owner()?, ctx.output().clone(), *ctx.branding());
    let mut ui = start_owner(
        owner,
        *ctx.branding(),
        Clipboard::Detect,
        Timings::default(),
    )?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, ui.stop.clone())
        .with_context(|| format!("{} ui could not catch Ctrl-C", ctx.branding().bin_name))?;
    let lines = ui.terminal.clone();
    let stop = ui.stop.clone();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if lines.send(line).is_err() {
                return;
            }
        }
        // End of input (Ctrl-D) quits, as Ctrl-C does.
        stop.store(true, Ordering::SeqCst);
    });
    let mut opened = !open_browser;
    let mut out = std::io::stdout();
    let paint = Paint::for_terminal(true);
    let bin = ctx.branding().bin_name;
    // The feed ends when the loop does.
    for line in ui.feed.iter() {
        let _ = writeln!(out, "{}", paint_feed(paint, bin, &line));
        let _ = out.flush();
        if !opened && let Some(url) = link_in(&line) {
            opened = true;
            if open(url).is_err() {
                let _ = writeln!(out, "  (could not open a browser: open the link yourself)");
            }
        }
    }
    ui.stop();
    Ok(())
}

/// A feed line coloured for the terminal: the timestamp muted, a link or a
/// one-time code in the accent, `done:` green, a refusal or failure in the
/// warning colour, the banner bold. The line itself is unchanged: the feed
/// is plain text, and tests read it as such.
fn paint_feed(paint: Paint, bin: &str, line: &str) -> String {
    if paint == Paint::PLAIN {
        return line.to_owned();
    }
    let (stamp, rest) = match line.split_at_checked(10) {
        Some((s, r)) if is_clock(s) => (paint.apply(Role::Muted, &s[..8]) + "  ", r),
        _ => (String::new(), line),
    };
    let body = if line.starts_with(&format!("{bin} ui ")) {
        paint.apply(Role::Bold, rest)
    } else if let Some(i) = rest.find("└─ done:") {
        let (head, tail) = rest.split_at(i + "└─ ".len());
        format!("{head}{}", paint.apply(Role::Ok, tail))
    } else if let Some(i) = rest.find("└─ ").filter(|_| {
        rest.contains("failed:") || rest.contains("not confirmed") || rest.contains("no answer")
    }) {
        let (head, tail) = rest.split_at(i + "└─ ".len());
        format!("{head}{}", paint.apply(Role::Warn, tail))
    } else if let Some(i) = rest.find("code      ") {
        let at = i + "code      ".len();
        let code_len = rest[at..].find(' ').unwrap_or(rest.len() - at);
        format!(
            "{}{}{}",
            &rest[..at],
            paint.apply(Role::Accent, &rest[at..at + code_len]),
            &rest[at + code_len..]
        )
    } else if let Some(url) = rest.split_whitespace().find(|w| w.starts_with("http")) {
        rest.replacen(url, &paint.apply(Role::Accent, url), 1)
    } else {
        rest.to_owned()
    };
    stamp + &body
}

/// `HH:MM:SS` and two spaces, as the feed's event lines start.
fn is_clock(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[2] == b':'
        && b[5] == b':'
        && &b[8..] == b"  "
        && [0, 1, 3, 4, 6, 7].iter().all(|&i| b[i].is_ascii_digit())
}

/// The one-time link in a feed line, if it has one.
fn link_in(line: &str) -> Option<&str> {
    let start = line.find("http://127.0.0.1:")?;
    let link = line[start..].split_whitespace().next()?;
    link.contains("/#c=").then_some(link)
}

fn open(url: &str) -> std::io::Result<()> {
    let program = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    Command::new(program)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_link() {
        assert_eq!(
            link_in("  page     http://127.0.0.1:5000/#c=abc  "),
            Some("http://127.0.0.1:5000/#c=abc")
        );
        assert_eq!(link_in("  server   http://127.0.0.1:8750"), None);
    }

    #[test]
    fn paints_the_feed_by_role() {
        let on = Paint::for_terminal(true);
        if on == Paint::PLAIN {
            // NO_COLOR or TERM=dumb in this environment: only the plain path.
            assert_eq!(
                paint_feed(on, "gv", "14:02:11  copy  x"),
                "14:02:11  copy  x"
            );
            return;
        }
        assert_eq!(
            paint_feed(on, "gv", "14:02:11  session   acme/prod  opened"),
            "\x1b[2m14:02:11\x1b[0m  session   acme/prod  opened"
        );
        assert_eq!(
            paint_feed(on, "gv", "  page     http://127.0.0.1:5000/#c=abc"),
            "  page     \x1b[36mhttp://127.0.0.1:5000/#c=abc\x1b[0m"
        );
        assert_eq!(
            paint_feed(
                on,
                "gv",
                "          │  code      4813   the browser must show the same code"
            ),
            "          │  code      \x1b[36m4813\x1b[0m   the browser must show the same code"
        );
        assert_eq!(
            paint_feed(on, "gv", "          └─ done: minted read token 7c1e"),
            "          └─ \x1b[32mdone: minted read token 7c1e\x1b[0m"
        );
        assert_eq!(
            paint_feed(on, "gv", "          └─ not confirmed; nothing was changed"),
            "          └─ \x1b[33mnot confirmed; nothing was changed\x1b[0m"
        );
        assert_eq!(
            paint_feed(on, "gv", "gv ui · galata-vault 0.1.0"),
            "\x1b[1mgv ui · galata-vault 0.1.0\x1b[0m"
        );
        assert_eq!(
            paint_feed(Paint::PLAIN, "gv", "          └─ done: x"),
            "          └─ done: x"
        );
    }
}
