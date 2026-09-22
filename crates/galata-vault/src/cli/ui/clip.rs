//! Copying without showing: a value goes from this process to the operating
//! system's clipboard on a tool's stdin, never as an argument, and is
//! cleared later only if the clipboard still holds it.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const TOOLS: &str = "pbcopy, wl-copy, xclip or xsel";

/// Where copies go.
#[derive(Debug, Clone)]
pub enum Clipboard {
    /// The platform's tool, found on `PATH`.
    Detect,
    /// Explicit programs, each with its arguments. Tests use a stand-in.
    Commands {
        /// The command that copies (reads the value on stdin).
        copy: Vec<String>,
        /// The command that pastes (prints the clipboard).
        paste: Vec<String>,
    },
    /// No clipboard: copying is disabled, and the page says so.
    Off,
}

struct Tool {
    copy: Vec<String>,
    paste: Vec<String>,
}

pub struct Clip {
    tool: Option<Tool>,
    clear_after: Duration,
    /// When to clear, and the digest of what was copied.
    due: Vec<(Instant, [u8; 32])>,
}

impl Clip {
    pub fn new(clipboard: Clipboard, clear_after: Duration) -> Clip {
        let tool = match clipboard {
            Clipboard::Detect => detect(),
            Clipboard::Commands { copy, paste } if !copy.is_empty() && !paste.is_empty() => {
                Some(Tool { copy, paste })
            }
            Clipboard::Commands { .. } | Clipboard::Off => None,
        };
        Clip {
            tool,
            clear_after,
            due: Vec::new(),
        }
    }

    pub fn available(&self) -> bool {
        self.tool.is_some()
    }

    pub fn clears_in(&self) -> u64 {
        self.clear_after.as_secs()
    }

    pub fn copy(&mut self, value: &[u8]) -> anyhow::Result<()> {
        let tool = self.tool.as_ref().with_context(|| {
            format!("copying needs {TOOLS}, and none was found; reveal the value instead")
        })?;
        write_to(&tool.copy, value)?;
        let digest: [u8; 32] = Sha256::digest(value).into();
        self.due.retain(|(_, d)| d != &digest);
        self.due.push((Instant::now() + self.clear_after, digest));
        Ok(())
    }

    /// Clear what is due, if the clipboard still holds it.
    pub fn tick(&mut self) {
        let now = Instant::now();
        let (due, later): (Vec<_>, Vec<_>) = self.due.drain(..).partition(|(at, _)| *at <= now);
        self.due = later;
        for (_, digest) in due {
            self.clear_if(&digest);
        }
    }

    /// Clear everything still pending, now: `gv ui` is stopping.
    pub fn clear_all(&mut self) {
        for (_, digest) in std::mem::take(&mut self.due) {
            self.clear_if(&digest);
        }
    }

    fn clear_if(&self, digest: &[u8; 32]) {
        let Some(tool) = &self.tool else { return };
        let Ok(current) = read_from(&tool.paste) else {
            return;
        };
        // Something the user copied since stays where it is.
        if Sha256::digest(&*current).as_slice() == digest {
            let _ = write_to(&tool.copy, b"");
        }
    }
}

fn write_to(argv: &[String], input: &[u8]) -> anyhow::Result<()> {
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("could not run {}", argv[0]))?;
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(input)
        .with_context(|| format!("could not write to {}", argv[0]))?;
    if !child.wait()?.success() {
        bail!("{} failed", argv[0]);
    }
    Ok(())
}

fn read_from(argv: &[String]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let out = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .with_context(|| format!("could not run {}", argv[0]))?;
    if !out.status.success() {
        bail!("{} failed", argv[0]);
    }
    Ok(Zeroizing::new(out.stdout))
}

fn on_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|d| d.join(program).is_file()))
}

fn detect() -> Option<Tool> {
    let tool = |copy: &[&str], paste: &[&str]| {
        Some(Tool {
            copy: copy.iter().map(|s| (*s).to_owned()).collect(),
            paste: paste.iter().map(|s| (*s).to_owned()).collect(),
        })
    };
    if cfg!(target_os = "macos") && on_path("pbcopy") && on_path("pbpaste") {
        return tool(&["pbcopy"], &["pbpaste"]);
    }
    if std::env::var_os("WAYLAND_DISPLAY").is_some() && on_path("wl-copy") && on_path("wl-paste") {
        return tool(&["wl-copy"], &["wl-paste", "--no-newline"]);
    }
    if on_path("xclip") {
        return tool(
            &["xclip", "-selection", "clipboard"],
            &["xclip", "-selection", "clipboard", "-o"],
        );
    }
    if on_path("xsel") {
        return tool(
            &["xsel", "--clipboard", "--input"],
            &["xsel", "--clipboard", "--output"],
        );
    }
    None
}
