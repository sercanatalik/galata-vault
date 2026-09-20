//! What a command reaches the world through: the key store, the state store,
//! the transport, the prompter and the output. [`Context::new`] gives the
//! host's own (the OS keychain or a 0600 file, the home directory's files,
//! HTTP, the terminal, stdout and stderr); a test or an embedding binary
//! replaces any of them with [`ContextBuilder`].

use std::collections::VecDeque;
use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::bail;
use galata_vault::owner::{Connector, InitError, Owner};
use galata_vault::{
    Api, ClientBuilder, Error, Events, FileStateStore, KeyStore, Progress, StateStore, Warning,
    code,
};
use zeroize::Zeroizing;

use crate::branding::Branding;
use crate::config::Home;
use crate::keystore::{CredentialsFile, LazyKeyStore};
use crate::style::{Paint, Role};
use crate::util::fmt_time;

/// Where a command's output goes. `Send + Sync`: warnings reach it from the
/// SDK's observer.
pub trait Output: Send + Sync {
    /// Write to standard output.
    fn stdout(&self, bytes: &[u8]) -> std::io::Result<()>;
    /// Write to standard error.
    fn stderr(&self, bytes: &[u8]) -> std::io::Result<()>;
    /// Whether standard output is a terminal (`gv get` then ends the value
    /// with a newline).
    fn stdout_is_terminal(&self) -> bool {
        false
    }
    /// Whether standard error is a terminal: messages are then coloured,
    /// unless `NO_COLOR` is set.
    fn stderr_is_terminal(&self) -> bool {
        false
    }
}

/// The process's stdout and stderr.
#[derive(Debug, Clone, Copy, Default)]
pub struct StdOutput;

impl Output for StdOutput {
    fn stdout(&self, bytes: &[u8]) -> std::io::Result<()> {
        let mut out = std::io::stdout().lock();
        out.write_all(bytes)?;
        out.flush()
    }

    fn stderr(&self, bytes: &[u8]) -> std::io::Result<()> {
        let mut err = std::io::stderr().lock();
        err.write_all(bytes)?;
        err.flush()
    }

    fn stdout_is_terminal(&self) -> bool {
        std::io::stdout().is_terminal()
    }

    fn stderr_is_terminal(&self) -> bool {
        std::io::stderr().is_terminal()
    }
}

/// Output kept in memory, for tests.
#[derive(Debug, Default)]
pub struct CapturedOutput {
    out: Mutex<Vec<u8>>,
    err: Mutex<Vec<u8>>,
}

impl CapturedOutput {
    /// Nothing captured yet.
    pub fn new() -> CapturedOutput {
        CapturedOutput::default()
    }

    /// Everything written to stdout.
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.out.lock().unwrap_or_else(|p| p.into_inner())).into_owned()
    }

    /// Everything written to stderr.
    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.err.lock().unwrap_or_else(|p| p.into_inner())).into_owned()
    }
}

impl Output for CapturedOutput {
    fn stdout(&self, bytes: &[u8]) -> std::io::Result<()> {
        self.out
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend_from_slice(bytes);
        Ok(())
    }

    fn stderr(&self, bytes: &[u8]) -> std::io::Result<()> {
        self.err
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend_from_slice(bytes);
        Ok(())
    }
}

/// Where a command's input comes from: confirmations, secret values and
/// bodies. Never an argument.
pub trait Prompter {
    /// Whether stdin is a terminal (a secret value is then asked for with a
    /// no-echo prompt).
    fn stdin_is_terminal(&self) -> bool;
    /// One line (a confirmation); its prompt is already on stderr.
    fn read_line(&mut self) -> std::io::Result<String>;
    /// A secret typed at a no-echo prompt.
    fn read_secret(&mut self, prompt: &str) -> std::io::Result<Zeroizing<String>>;
    /// All of stdin.
    fn read_to_end(&mut self) -> std::io::Result<Zeroizing<Vec<u8>>>;
}

/// The terminal: stdin, and `rpassword` for no-echo prompts.
#[derive(Debug, Clone, Copy, Default)]
pub struct TtyPrompter;

impl Prompter for TtyPrompter {
    fn stdin_is_terminal(&self) -> bool {
        std::io::stdin().is_terminal()
    }

    fn read_line(&mut self) -> std::io::Result<String> {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        Ok(line)
    }

    fn read_secret(&mut self, prompt: &str) -> std::io::Result<Zeroizing<String>> {
        rpassword::prompt_password(prompt).map(Zeroizing::new)
    }

    fn read_to_end(&mut self) -> std::io::Result<Zeroizing<Vec<u8>>> {
        let mut buf = Zeroizing::new(Vec::new());
        std::io::stdin().lock().read_to_end(&mut buf)?;
        Ok(buf)
    }
}

/// Answers from a script, for tests: lines for confirmations and no-echo
/// prompts, and bytes for stdin.
#[derive(Default)]
pub struct ScriptedPrompter {
    lines: VecDeque<String>,
    stdin: Zeroizing<Vec<u8>>,
    terminal: bool,
}

impl std::fmt::Debug for ScriptedPrompter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScriptedPrompter")
            .field("lines", &self.lines.len())
            .field("stdin", &self.stdin.len())
            .field("terminal", &self.terminal)
            .finish()
    }
}

impl ScriptedPrompter {
    /// An empty script: no lines, empty stdin, not a terminal.
    pub fn new() -> ScriptedPrompter {
        ScriptedPrompter::default()
    }

    /// Answer the next confirmation or prompt with `line`.
    pub fn line(mut self, line: impl Into<String>) -> ScriptedPrompter {
        self.lines.push_back(line.into());
        self
    }

    /// Stdin holds `bytes`.
    pub fn stdin(mut self, bytes: impl Into<Vec<u8>>) -> ScriptedPrompter {
        self.stdin = Zeroizing::new(bytes.into());
        self
    }

    /// Pretend stdin is a terminal (values are then read as prompted lines).
    pub fn terminal(mut self, on: bool) -> ScriptedPrompter {
        self.terminal = on;
        self
    }
}

impl Prompter for ScriptedPrompter {
    fn stdin_is_terminal(&self) -> bool {
        self.terminal
    }

    fn read_line(&mut self) -> std::io::Result<String> {
        self.lines.pop_front().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the script has no more lines",
            )
        })
    }

    fn read_secret(&mut self, _prompt: &str) -> std::io::Result<Zeroizing<String>> {
        self.read_line().map(Zeroizing::new)
    }

    fn read_to_end(&mut self) -> std::io::Result<Zeroizing<Vec<u8>>> {
        Ok(std::mem::take(&mut self.stdin))
    }
}

/// Every line of `message` on stderr, each prefixed `<prefix>: `. On a
/// terminal the prefix is muted and a line that starts `warning:` is in the
/// warning colour; `role` paints the whole message instead.
pub(crate) fn say(output: &dyn Output, prefix: &str, message: &str) {
    say_as(output, prefix, None, message);
}

pub(crate) fn say_as(output: &dyn Output, prefix: &str, role: Option<Role>, message: &str) {
    let paint = Paint::for_terminal(output.stderr_is_terminal());
    let prefix = paint.apply(Role::Muted, &format!("{prefix}:"));
    for line in message.split('\n') {
        let role = role.or_else(|| line.starts_with("warning:").then_some(Role::Warn));
        let line = match role {
            Some(role) => paint.apply(role, line),
            None => line.to_owned(),
        };
        let _ = output.stderr(format!("{prefix} {line}\n").as_bytes());
    }
}

/// The SDK's notices, as `gv` prints them to stderr.
pub(crate) struct CliEvents {
    output: Arc<dyn Output>,
    branding: Branding,
    expiry: bool,
    progress: bool,
}

impl CliEvents {
    /// `expiry` and `progress` say whether those are shown; warnings always
    /// are.
    pub(crate) fn new(
        output: Arc<dyn Output>,
        branding: Branding,
        expiry: bool,
        progress: bool,
    ) -> CliEvents {
        CliEvents {
            output,
            branding,
            expiry,
            progress,
        }
    }

    fn say(&self, message: &str) {
        say(&*self.output, self.branding.message_prefix, message);
    }
}

impl Events for CliEvents {
    fn progress(&self, event: &Progress) {
        if !self.progress {
            return;
        }
        let bin = self.branding.bin_name;
        match event {
            Progress::ProofOfWork { label, .. } => {
                self.say(&format!(
                    "solving the proof-of-work for {label} (a few seconds)…"
                ));
            }
            Progress::Deleted { path } => self.say(&format!("deleted {path}")),
            Progress::Relinked { path, parent } => self.say(&format!(
                "relinked {path} in {parent}'s children record (the entry predated a rekey)"
            )),
            Progress::RekeyPlanned {
                path,
                nodes,
                tokens,
                kit,
            } => self.say(&format!(
                "rekeying {path}: {nodes} environment(s) move to fresh vaults under a new key, and {tokens} token(s) die\n\
                 with the old vaults. The new kit is {kit} (mode 0600); if this stops, `{bin} rekey --resume` finishes it."
            )),
            _ => {}
        }
    }

    fn expiry(&self, label: &str, expires_at: i64) {
        if self.expiry {
            self.say(&format!(
                "warning: {label} expires at {} unless it is used before then",
                fmt_time(expires_at)
            ));
        }
    }

    fn warning(&self, warning: &Warning) {
        let bin = self.branding.bin_name;
        match warning {
            Warning::KeepAliveFailed { path, message } => {
                self.say(&format!("warning: keeping {path} alive failed: {message}"));
            }
            Warning::Unreachable {
                path,
                message,
                vault_missing,
            } => {
                if *vault_missing {
                    self.say(&format!(
                        "warning: {message}; `{bin} env repair {path}` re-creates an expired vault"
                    ));
                } else {
                    self.say(&format!("warning: {message}"));
                }
            }
            Warning::ChildTooDeep { parent, message } => self.say(&format!(
                "warning: {parent} lists a child that is too deep: {message}"
            )),
            Warning::SealedKeyUnopenable { path, message } => {
                self.say(&format!("warning: {path}'s sealed key does not open: {message}"));
            }
            Warning::RelinkFailed {
                path,
                parent,
                message,
            } => self.say(&format!(
                "warning: {path} opens with its stored key, but relinking it in {parent} failed: {message}"
            )),
            Warning::Detached { path, parent } => self.say(&format!(
                "warning: {path} is now detached: the key for {parent} is not held here, so its owner no longer\n\
                 reaches {path} or anything beneath it. You are now its only owner."
            )),
            // Printed by `token revoke` after its own line, from the outcome.
            Warning::ForwardOnlyRevocation { .. } => {}
            _ => {}
        }
    }
}

/// An SDK error in `gv`'s words: the SDK's message, with the command hints
/// `gv` has always given.
pub(crate) fn describe(e: &Error, b: &Branding) -> String {
    let bin = b.bin_name;
    match e {
        Error::UnknownPath {
            path,
            suggestion,
            project_known,
            ..
        } => {
            let hint = suggestion
                .as_ref()
                .map_or(String::new(), |s| format!("; did you mean {s}?"));
            let project = path.split('/').next().unwrap_or(path);
            if *project_known {
                format!(
                    "unknown environment {path}{hint} (`{bin} env ls {project}` refreshes the tree; `{bin} env add {path}` creates it)"
                )
            } else {
                format!("unknown project {project}{hint}")
            }
        }
        Error::VaultNotFound { label, message } => {
            format!("{message}; `{bin} env repair {label}` re-creates an expired vault")
        }
        Error::Invalid { code, message } => match *code {
            code::UNKNOWN_PROJECT => {
                format!("{message} ({bin} init, {bin} recover or {bin} key import)")
            }
            code::HAS_CHILDREN => format!("{message}; pass --recursive to delete them too"),
            code::IS_PROJECT => format!("{message}; create it with {bin} init"),
            code::REKEY_IN_PROGRESS => format!(
                "{message}; finish it with `{bin} rekey --resume` or undo it with `{bin} rekey --abort`"
            ),
            code::REKEY_FORWARD_ONLY => format!("{message}; finish it with `{bin} rekey --resume`"),
            _ => message.clone(),
        },
        other => other.to_string(),
    }
}

/// A command's error as `gv` prints it: each context layer, then the SDK
/// error in `gv`'s words, `: `-separated. An SDK error's sources are already
/// in its message.
pub fn render_error(e: &anyhow::Error, branding: &Branding) -> String {
    let mut parts = Vec::new();
    for cause in e.chain() {
        if let Some(sdk) = cause.downcast_ref::<Error>() {
            parts.push(describe(sdk, branding));
            break;
        }
        if let Some(init) = cause.downcast_ref::<InitError>() {
            parts.push(describe(init.error(), branding));
            break;
        }
        parts.push(cause.to_string());
    }
    parts.join(": ")
}

/// Everything a command reaches the world through.
pub struct Context {
    branding: Branding,
    home: Result<Home, String>,
    output: Arc<dyn Output>,
    prompter: Box<dyn Prompter>,
    keys: Option<Arc<dyn KeyStore>>,
    state: Option<Arc<dyn StateStore>>,
    connect: Option<Connector>,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("branding", &self.branding.bin_name)
            .field("home", &self.home)
            .finish_non_exhaustive()
    }
}

/// Builds a [`Context`], replacing any of the host's defaults.
pub struct ContextBuilder {
    branding: Branding,
    home: Option<PathBuf>,
    output: Option<Arc<dyn Output>>,
    prompter: Option<Box<dyn Prompter>>,
    keys: Option<Arc<dyn KeyStore>>,
    state: Option<Arc<dyn StateStore>>,
    connect: Option<Connector>,
    credentials_file: bool,
}

impl std::fmt::Debug for ContextBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContextBuilder")
            .field("branding", &self.branding.bin_name)
            .field("home", &self.home)
            .finish_non_exhaustive()
    }
}

impl ContextBuilder {
    /// The host's defaults for `branding`.
    pub fn new(branding: Branding) -> ContextBuilder {
        ContextBuilder {
            branding,
            home: None,
            output: None,
            prompter: None,
            keys: None,
            state: None,
            connect: None,
            credentials_file: false,
        }
    }

    /// Keep files in `dir` instead of the home the environment names.
    pub fn home(mut self, dir: impl Into<PathBuf>) -> ContextBuilder {
        self.home = Some(dir.into());
        self
    }

    /// Write stdout and stderr through `output`.
    pub fn output(mut self, output: Arc<dyn Output>) -> ContextBuilder {
        self.output = Some(output);
        self
    }

    /// Read confirmations, values and bodies through `prompter`.
    pub fn prompter(mut self, prompter: impl Prompter + 'static) -> ContextBuilder {
        self.prompter = Some(Box::new(prompter));
        self
    }

    /// Keep node keys in `keys` instead of the OS keychain or the
    /// credentials file.
    pub fn key_store(mut self, keys: Arc<dyn KeyStore>) -> ContextBuilder {
        self.keys = Some(keys);
        self
    }

    /// Keep local state in `state` instead of the home's files.
    pub fn state_store(mut self, state: Arc<dyn StateStore>) -> ContextBuilder {
        self.state = Some(state);
        self
    }

    /// Reach each server through `connect` instead of plain HTTP (a proxy,
    /// a private CA, a test transport).
    pub fn connector(
        mut self,
        connect: impl Fn(&str) -> Result<Api, Error> + Send + Sync + 'static,
    ) -> ContextBuilder {
        self.connect = Some(Arc::new(connect));
        self
    }

    /// Keep keys in the home's 0600 credentials file, whatever the
    /// environment says.
    pub fn credentials_file(mut self, on: bool) -> ContextBuilder {
        self.credentials_file = on;
        self
    }

    /// The context. A home that cannot be found is an error only when a
    /// command needs it.
    pub fn build(self) -> Context {
        let home = match self.home {
            Some(dir) => Ok(Home { dir }),
            None => Home::locate(&self.branding).map_err(|e| e.to_string()),
        };
        let output = self.output.unwrap_or_else(|| Arc::new(StdOutput));
        let keys = self.keys.or_else(|| {
            let h = home.as_ref().ok()?;
            Some(if self.credentials_file {
                Arc::new(CredentialsFile::new(h.credentials_path())) as Arc<dyn KeyStore>
            } else {
                Arc::new(LazyKeyStore::new(h.clone(), self.branding, output.clone()))
            })
        });
        let state = self.state.or_else(|| {
            home.as_ref()
                .ok()
                .map(|h| Arc::new(FileStateStore::new(&h.dir)) as Arc<dyn StateStore>)
        });
        Context {
            branding: self.branding,
            home,
            output,
            prompter: self.prompter.unwrap_or_else(|| Box::new(TtyPrompter)),
            keys,
            state,
            connect: self.connect,
        }
    }
}

impl Context {
    /// The host's context for `branding`: the OS keychain (or the 0600
    /// credentials file), the home directory's state files, HTTP, the
    /// terminal, stdout and stderr.
    pub fn new(branding: Branding) -> Context {
        ContextBuilder::new(branding).build()
    }

    /// A builder replacing any of the host's defaults.
    pub fn builder(branding: Branding) -> ContextBuilder {
        ContextBuilder::new(branding)
    }

    /// The branding.
    pub fn branding(&self) -> &Branding {
        &self.branding
    }

    /// The home directory.
    pub fn home(&self) -> anyhow::Result<&Path> {
        match &self.home {
            Ok(h) => Ok(&h.dir),
            Err(e) => bail!("{e}"),
        }
    }

    /// Where output goes.
    pub fn output(&self) -> &Arc<dyn Output> {
        &self.output
    }

    /// The observer that prints the SDK's notices.
    pub fn events(&self) -> Arc<dyn Events> {
        Arc::new(CliEvents::new(
            self.output.clone(),
            self.branding,
            true,
            true,
        ))
    }

    /// The key store. Without a home and without one given, the error says
    /// why no home was found.
    pub fn key_store(&self) -> anyhow::Result<Arc<dyn KeyStore>> {
        match &self.keys {
            Some(k) => Ok(k.clone()),
            None => Err(self.no_home()),
        }
    }

    /// The state store. Without a home and without one given, the error says
    /// why no home was found.
    pub fn state_store(&self) -> anyhow::Result<Arc<dyn StateStore>> {
        match &self.state {
            Some(s) => Ok(s.clone()),
            None => Err(self.no_home()),
        }
    }

    fn no_home(&self) -> anyhow::Error {
        match &self.home {
            Err(e) => anyhow::anyhow!("{e}"),
            Ok(h) => anyhow::anyhow!("no store for {}", h.dir.display()),
        }
    }

    /// The owner API over this context's stores, transport and output.
    pub fn owner(&self) -> anyhow::Result<Owner> {
        self.owner_over(self.state_store()?)
    }

    /// The owner API over `state` instead of the context's state store.
    pub fn owner_over(&self, state: Arc<dyn StateStore>) -> anyhow::Result<Owner> {
        let owner = Owner::open(self.key_store()?, state)?.with_events(self.events());
        Ok(match &self.connect {
            Some(c) => {
                let c = c.clone();
                owner.with_connector(move |s| c(s))
            }
            None => owner,
        })
    }

    /// The typed API for `server`, reporting to this context's output.
    pub fn api(&self, server: &str) -> anyhow::Result<Api> {
        let api = match &self.connect {
            Some(c) => c(server)?,
            None => ClientBuilder::new(server).build()?,
        };
        Ok(api.with_events(self.events()))
    }

    /// Print `message` on stderr, each line prefixed with the message
    /// prefix (`gv: `).
    pub fn say(&self, message: &str) {
        say(&*self.output, self.branding.message_prefix, message);
    }

    /// [`Context::say`], for good news (a verified chain): green on a
    /// terminal.
    pub(crate) fn say_ok(&self, message: &str) {
        say_as(
            &*self.output,
            self.branding.message_prefix,
            Some(Role::Ok),
            message,
        );
    }

    /// Print one line on stderr as it is.
    pub(crate) fn say_raw(&self, line: &str) {
        let _ = self.output.stderr(format!("{line}\n").as_bytes());
    }

    /// Write to stdout.
    pub(crate) fn out(&self, bytes: &[u8]) -> anyhow::Result<()> {
        Ok(self.output.stdout(bytes)?)
    }

    /// Write one line to stdout.
    pub(crate) fn out_line(&self, line: &str) -> anyhow::Result<()> {
        self.out(format!("{line}\n").as_bytes())
    }

    /// The prompter.
    pub(crate) fn prompter(&mut self) -> &mut dyn Prompter {
        &mut *self.prompter
    }

    /// The variable `<prefix><name>`, if set and not empty.
    pub(crate) fn var(&self, name: &str) -> Option<String> {
        std::env::var(self.branding.var(name))
            .ok()
            .filter(|v| !v.is_empty())
    }

    /// An SDK error in this binary's words.
    pub(crate) fn describe(&self, e: &Error) -> String {
        describe(e, &self.branding)
    }

    /// Ask on stderr and read one line; succeed only on `expected`.
    pub(crate) fn confirm(&mut self, prompt: &str, expected: &str) -> anyhow::Result<()> {
        self.output.stderr(format!("{prompt} ").as_bytes())?;
        let line = self.prompter.read_line()?;
        if line.trim() != expected {
            bail!("not confirmed; nothing was changed");
        }
        Ok(())
    }

    /// A secret value: from a no-echo prompt on a terminal, else all of
    /// stdin. Never from an argument.
    pub(crate) fn read_value(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let value = if self.prompter.stdin_is_terminal() {
            let typed = self.prompter.read_secret(&format!("Value for {name}: "))?;
            Zeroizing::new(typed.as_bytes().to_vec())
        } else {
            self.prompter.read_to_end()?
        };
        if value.is_empty() {
            bail!("the value for {name} is empty; pipe it on stdin or type it at the prompt");
        }
        Ok(value)
    }
}
