//! Local bookkeeping, supplied by the caller.
//!
//! [`LocalState`] is what an owner remembers between runs, and holds no key
//! material:
//! - the projects: each one's pinned server, the paths whose keys are held,
//!   and the known tree (path → vault id, and whether the key is sealed);
//! - when each vault was last kept alive, and which servers announce no
//!   expiry;
//! - the audit heads verified, and the pins (descriptor and last-seen record
//!   versions) that catch a server rolling back;
//! - a rekey in progress, so it can be resumed or aborted.
//!
//! [`FileStateStore`] keeps it in the `config.toml` and `state.toml` of a
//! directory, exactly as `gv` always has, so an existing `gv` home loads
//! unchanged. On Unix both files are written with mode 0600; elsewhere they
//! are written without mode bits.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::proto::audit::ChainHead;
use crate::proto::ids::VaultId;
use crate::proto::path::EnvPath;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::{Error, code};
use crate::store::StoreError;
use crate::vault::Pins;

/// The local state format this crate reads and writes.
pub const FORMAT_VERSION: u32 = 1;

/// Everything an owner remembers between runs. No key material, ever.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct LocalState {
    /// Project name → its pinned server, held paths and known tree.
    #[serde(default)]
    pub projects: BTreeMap<String, ProjectState>,
    /// Vault id (hex) → when this client last kept it alive.
    #[serde(default)]
    pub touched: BTreeMap<String, i64>,
    /// Vault id (hex) → the audit head this client last verified.
    #[serde(default)]
    pub audit: BTreeMap<String, ChainHead>,
    /// Vault ids whose server announced no expiry at their last status;
    /// keep-alive skips them.
    #[serde(default)]
    pub no_expiry: BTreeSet<String>,
    /// Vault id (hex) → the descriptor and latest record versions this
    /// client saw there.
    #[serde(default)]
    pub pins: BTreeMap<String, Pins>,
    /// A re-root in progress, if any.
    #[serde(default)]
    pub rekey: Option<RekeyPlan>,
}

/// One project: its pinned server, the paths whose keys are held, and the
/// known tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ProjectState {
    /// Pinned at init, import or recover; never taken from anywhere else.
    pub server: String,
    /// Paths whose keys are in the key store: the project root, or nodes
    /// imported from delegation kits.
    #[serde(default)]
    pub held: Vec<String>,
    /// The known tree, path → vault. Refreshed by rediscovery.
    #[serde(default)]
    pub tree: BTreeMap<String, TreeNode>,
}

/// A known environment's vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct TreeNode {
    /// Its vault id.
    pub vault_id: VaultId,
    /// Its key is sealed in its parent's children record (after a rekey)
    /// rather than derived.
    #[serde(default)]
    pub sealed: bool,
}

impl TreeNode {
    /// A node of the tree.
    pub fn new(vault_id: VaultId, sealed: bool) -> TreeNode {
        TreeNode { vault_id, sealed }
    }
}

/// Where a re-root stands, so an interrupted one can be resumed or aborted.
/// It holds no key: the old and new root keys wait in the key store, and the
/// new one is in the kit the caller stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RekeyPlan {
    /// The re-rooted node.
    pub path: String,
    /// Where the caller stored the new kit, before any change on the server.
    pub kit: PathBuf,
    /// The subtree, relative to `path` ("" is the node itself), parents
    /// before children.
    pub nodes: Vec<String>,
    /// Each node's vault before the re-root, in `nodes` order.
    pub old_ids: Vec<VaultId>,
    /// Each node's vault after it, in `nodes` order.
    pub new_ids: Vec<VaultId>,
    /// The tokens that die with the old vaults: "path  scope  id".
    #[serde(default)]
    pub remint: Vec<String>,
    /// The last step completed.
    pub step: RekeyStep,
    /// Whether the parent's children record now seals the new key.
    #[serde(default)]
    pub linked: bool,
}

/// The last step a re-root completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum RekeyStep {
    /// The kit is stored and the keys are in the key store; nothing changed yet.
    Planned,
    /// Every new vault exists.
    Created,
    /// Every record is copied, and every new children record written.
    Migrated,
    /// The parent points at the new key, or the node is detached.
    Linked,
    /// Every old vault is deleted.
    Retired,
}

impl RekeyStep {
    /// The step's name, as it appears in `state.toml`.
    pub fn as_str(self) -> &'static str {
        match self {
            RekeyStep::Planned => "planned",
            RekeyStep::Created => "created",
            RekeyStep::Migrated => "migrated",
            RekeyStep::Linked => "linked",
            RekeyStep::Retired => "retired",
        }
    }
}

impl ProjectState {
    /// A project pinned to `server`, with nothing held or known yet.
    pub fn new(server: impl Into<String>) -> ProjectState {
        ProjectState {
            server: server.into(),
            held: Vec::new(),
            tree: BTreeMap::new(),
        }
    }

    /// Whether `path` is in the known tree.
    pub fn knows(&self, path: &EnvPath) -> bool {
        self.tree.contains_key(&path.to_string())
    }

    /// The deepest held path at or above `path`.
    pub fn held_root_for(&self, path: &EnvPath) -> Option<EnvPath> {
        self.held
            .iter()
            .filter_map(|h| h.parse::<EnvPath>().ok())
            .filter(|h| path.starts_with(h))
            .max_by_key(EnvPath::depth)
    }

    /// Known paths strictly below `path`, deepest first.
    pub fn descendants(&self, path: &EnvPath) -> Vec<EnvPath> {
        let mut out: Vec<EnvPath> = self
            .tree
            .keys()
            .filter_map(|k| k.parse::<EnvPath>().ok())
            .filter(|k| k != path && k.starts_with(path))
            .collect();
        out.sort_by_key(|p| std::cmp::Reverse(p.depth()));
        out
    }

    /// Known paths directly below `path`.
    pub fn children_of(&self, path: &EnvPath) -> Vec<EnvPath> {
        self.descendants(path)
            .into_iter()
            .filter(|p| p.depth() == path.depth() + 1)
            .collect()
    }
}

impl LocalState {
    /// The project `path` belongs to.
    pub fn project(&self, path: &EnvPath) -> Result<&ProjectState, Error> {
        let name = path.project_name().as_str();
        self.projects.get(name).ok_or_else(|| unknown_project(name))
    }

    /// The project `path` belongs to, to change.
    pub fn project_mut(&mut self, path: &EnvPath) -> Result<&mut ProjectState, Error> {
        let name = path.project_name().as_str().to_owned();
        self.projects
            .get_mut(&name)
            .ok_or_else(|| unknown_project(&name))
    }

    /// Every known path across all projects.
    pub fn known_paths(&self) -> Vec<String> {
        self.projects
            .values()
            .flat_map(|p| p.tree.keys().cloned())
            .collect()
    }

    /// The server of the project whose tree holds `vault`.
    pub fn server_for_vault(&self, vault: &VaultId) -> Option<&str> {
        self.projects
            .values()
            .find(|p| p.tree.values().any(|n| n.vault_id == *vault))
            .map(|p| p.server.as_str())
    }
}

fn unknown_project(name: &str) -> Error {
    Error::local(
        code::UNKNOWN_PROJECT,
        format!("no project {name:?} is configured here"),
    )
}

/// Keeps [`LocalState`]. `load` of a store that holds nothing yet returns the
/// default (empty) state.
pub trait StateStore: Send + Sync {
    /// The state as last saved.
    fn load(&self) -> Result<LocalState, StoreError>;
    /// Save the whole state.
    fn save(&self, state: &LocalState) -> Result<(), StoreError>;
}

impl<S: StateStore + ?Sized> StateStore for std::sync::Arc<S> {
    fn load(&self) -> Result<LocalState, StoreError> {
        (**self).load()
    }

    fn save(&self, state: &LocalState) -> Result<(), StoreError> {
        (**self).save(state)
    }
}

/// `config.toml` and `state.toml` in one directory: `gv`'s layout.
#[derive(Debug, Clone)]
pub struct FileStateStore {
    dir: PathBuf,
}

/// `config.toml`: which projects exist, their servers and trees.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    /// Implicit (1) when absent, and never written until the format changes,
    /// so older builds keep reading files this one wrote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<u32>,
    #[serde(default)]
    projects: BTreeMap<String, ProjectState>,
}

/// `state.toml`: bookkeeping that changes on every run.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateFile {
    #[serde(default)]
    touched: BTreeMap<String, i64>,
    #[serde(default)]
    audit: BTreeMap<String, ChainHead>,
    #[serde(default)]
    no_expiry: BTreeSet<String>,
    #[serde(default)]
    pins: BTreeMap<String, Pins>,
    #[serde(default)]
    rekey: Option<RekeyPlan>,
}

impl FileStateStore {
    /// The store in `dir` (created on the first save).
    pub fn new(dir: impl Into<PathBuf>) -> FileStateStore {
        FileStateStore { dir: dir.into() }
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// `<dir>/config.toml`.
    pub fn config_path(&self) -> PathBuf {
        self.dir.join("config.toml")
    }

    /// `<dir>/state.toml`.
    pub fn state_path(&self) -> PathBuf {
        self.dir.join("state.toml")
    }
}

fn load_toml<T: Default + DeserializeOwned>(path: &Path) -> Result<T, StoreError> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text)
            .map_err(|e| StoreError::with_source(format!("reading {}: {e}", path.display()), e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(StoreError::with_source(
            format!("reading {}: {e}", path.display()),
            e,
        )),
    }
}

fn save_toml<T: Serialize>(path: &Path, value: &T) -> Result<(), StoreError> {
    let text = toml::to_string(value)
        .map_err(|e| StoreError::with_source(format!("writing {}: {e}", path.display()), e))?;
    write_private(path, text.as_bytes())
}

/// Write `bytes` to `path` via a temporary file and a rename; on Unix the
/// file never exists with a mode other than 0600.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    use std::io::Write;
    let io = |what: &str, p: &Path, e: std::io::Error| {
        StoreError::with_source(format!("{what} {}: {e}", p.display()), e)
    };
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|e| io("creating", dir, e))?;
    }
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .map(|e| e.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    let _ = std::fs::remove_file(&tmp);
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options.open(&tmp).map_err(|e| io("creating", &tmp, e))?;
        f.write_all(bytes).map_err(|e| io("writing", &tmp, e))?;
        f.sync_all().map_err(|e| io("writing", &tmp, e))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| io("writing", path, e))
}

impl StateStore for FileStateStore {
    fn load(&self) -> Result<LocalState, StoreError> {
        let config: ConfigFile = load_toml(&self.config_path())?;
        if let Some(v) = config.version
            && v != FORMAT_VERSION
        {
            return Err(StoreError::new(format!(
                "{} is local state format {v}, which this build does not read (it reads {FORMAT_VERSION})",
                self.config_path().display()
            )));
        }
        let state: StateFile = load_toml(&self.state_path())?;
        Ok(LocalState {
            projects: config.projects,
            touched: state.touched,
            audit: state.audit,
            no_expiry: state.no_expiry,
            pins: state.pins,
            rekey: state.rekey,
        })
    }

    fn save(&self, state: &LocalState) -> Result<(), StoreError> {
        save_toml(
            &self.config_path(),
            &ConfigFile {
                version: None,
                projects: state.projects.clone(),
            },
        )?;
        save_toml(
            &self.state_path(),
            &StateFile {
                touched: state.touched.clone(),
                audit: state.audit.clone(),
                no_expiry: state.no_expiry.clone(),
                pins: state.pins.clone(),
                rekey: state.rekey.clone(),
            },
        )
    }
}

/// State in memory, for tests (feature `test-util`).
#[cfg(feature = "test-util")]
#[derive(Debug, Default)]
pub struct MemoryStateStore {
    state: std::sync::Mutex<LocalState>,
}

#[cfg(feature = "test-util")]
impl MemoryStateStore {
    /// An empty store.
    pub fn new() -> MemoryStateStore {
        MemoryStateStore::default()
    }
}

#[cfg(feature = "test-util")]
impl StateStore for MemoryStateStore {
    fn load(&self) -> Result<LocalState, StoreError> {
        Ok(self.state.lock().unwrap_or_else(|p| p.into_inner()).clone())
    }

    fn save(&self, state: &LocalState) -> Result<(), StoreError> {
        *self.state.lock().unwrap_or_else(|p| p.into_inner()) = state.clone();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::ids::Hash32;

    fn p(s: &str) -> EnvPath {
        s.parse().unwrap()
    }

    #[test]
    fn roundtrip_and_tree_queries() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStateStore::new(dir.path());
        let mut project = ProjectState::new("https://vault.example");
        project.held = vec!["acme".into(), "acme/prod/eu".into()];
        for (i, path) in ["acme", "acme/prod", "acme/prod/eu", "acme/dev"]
            .into_iter()
            .enumerate()
        {
            project
                .tree
                .insert(path.into(), TreeNode::new(VaultId([i as u8; 16]), false));
        }
        let mut state = LocalState::default();
        state.projects.insert("acme".into(), project);
        store.save(&state).unwrap();
        let back = store.load().unwrap();
        assert_eq!(back, state);
        let project = back.project(&p("acme/dev")).unwrap();

        assert_eq!(
            project.held_root_for(&p("acme/prod/eu")),
            Some(p("acme/prod/eu"))
        );
        assert_eq!(project.held_root_for(&p("acme/prod")), Some(p("acme")));
        assert_eq!(
            project.children_of(&p("acme")),
            [p("acme/dev"), p("acme/prod")]
        );
        assert_eq!(project.descendants(&p("acme"))[0], p("acme/prod/eu"));
        assert_eq!(
            back.project(&p("other/dev")).unwrap_err().code(),
            code::UNKNOWN_PROJECT
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for f in [store.config_path(), store.state_path()] {
                let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "{}", f.display());
            }
        }
        let text = std::fs::read_to_string(store.config_path()).unwrap();
        assert!(!text.contains("version"), "the version stays implicit");
    }

    /// A home as `gv` wrote it before this crate kept it: every project,
    /// tree node, keep-alive time, audit head, pin and rekey plan loads.
    #[test]
    fn a_home_written_by_gv_loads_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let a = "aa".repeat(16);
        let b = "bb".repeat(16);
        let hash = "cd".repeat(32);
        std::fs::write(
            dir.path().join("config.toml"),
            format!(
                "[projects.acme]\nserver = \"https://vault.example\"\nheld = [\"acme\"]\n\n\
                 [projects.acme.tree.acme]\nvault_id = \"{a}\"\n\n\
                 [projects.acme.tree.\"acme/dev\"]\nvault_id = \"{b}\"\nsealed = true\n"
            ),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("state.toml"),
            format!(
                "no_expiry = [\"{b}\"]\n\n[touched]\n{a} = 1757500000\n\n\
                 [audit.{a}]\nseq = 7\nhash = \"{hash}\"\n\n\
                 [pins.{a}.descriptor]\ngeneration = 2\nhash = \"{hash}\"\n\n\
                 [rekey]\npath = \"acme/dev\"\nkit = \"/tmp/acme-dev.gvkit\"\nnodes = [\"\"]\n\
                 old_ids = [\"{b}\"]\nnew_ids = [\"{a}\"]\nstep = \"created\"\n"
            ),
        )
        .unwrap();
        let state = FileStateStore::new(dir.path()).load().unwrap();
        let acme = &state.projects["acme"];
        assert_eq!(acme.server, "https://vault.example");
        assert_eq!(acme.held, ["acme"]);
        assert!(acme.tree["acme/dev"].sealed && !acme.tree["acme"].sealed);
        assert_eq!(state.touched[&a], 1_757_500_000);
        assert_eq!(state.audit[&a].seq, 7);
        assert_eq!(state.audit[&a].hash, Hash32::from_hex(&hash).unwrap());
        assert_eq!(state.pins[&a].descriptor.unwrap().generation, 2);
        assert!(state.no_expiry.contains(&b));
        let plan = state.rekey.as_ref().unwrap();
        assert_eq!(
            (plan.path.as_str(), plan.step),
            ("acme/dev", RekeyStep::Created)
        );

        // Saved again, it reads back the same, and an unknown key is refused
        // as before.
        let again = tempfile::tempdir().unwrap();
        FileStateStore::new(again.path()).save(&state).unwrap();
        assert_eq!(FileStateStore::new(again.path()).load().unwrap(), state);
        std::fs::write(dir.path().join("config.toml"), "surprise = 1\n").unwrap();
        assert!(FileStateStore::new(dir.path()).load().is_err());
        std::fs::write(dir.path().join("config.toml"), "version = 2\n").unwrap();
        let e = FileStateStore::new(dir.path()).load().unwrap_err();
        assert!(e.message().contains("format 2"), "{e}");
    }
}
