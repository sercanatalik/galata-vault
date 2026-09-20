//! The owner API: every operation `gv` performs as a project's owner, as
//! data in and data out.
//!
//! An [`Owner`] is built from a [`KeyStore`] (where held node keys live), a
//! [`StateStore`] (the known tree and bookkeeping), an optional
//! [`crate::Events`] observer, and a connector that reaches each project's
//! pinned server (by default [`galata_vault_client::ClientBuilder`] over HTTP).
//!
//! The library asks nothing and prints nothing:
//! - every confirmation `gv` asks for is a typestate or an argument: a new
//!   project's key is stored only after [`PendingInit::confirm_kit_stored`];
//!   exporting a delegation kit takes [`GrantsSubtreeOwnership`]; a rekey
//!   takes [`RetiresAllTokens`];
//! - every warning goes to the observer or into an outcome
//!   ([`Removal`], [`Repair`], [`RekeyOutcome`]);
//! - no key file is written: the caller stores the kits it is handed.
//!
//! ```no_run
//! use std::sync::Arc;
//! use galata_vault::owner::{Owner, RetiresAllTokens};
//! use galata_vault::{FileStateStore, KeyStore, Scope};
//! # fn keys() -> Arc<dyn KeyStore> { unimplemented!() }
//!
//! let mut owner = Owner::open(keys(), Arc::new(FileStateStore::new("/var/lib/acme")))?;
//! let init = owner.begin_init("acme", "https://vault.example")?;
//! let kit = init.recovery_kit().render()?; // store it somewhere safe first
//! # drop(kit);
//! init.confirm_kit_stored()?;
//! owner.env_add(&"acme/prod".parse()?)?;
//! let env = owner.environment(&"acme/prod".parse()?)?;
//! let token = env.mint(Scope::Read, 0, &[])?;
//! # let _ = (token, RetiresAllTokens);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod env;
pub(crate) mod kit;
mod rekey;

pub use env::{Environment, MintedToken, Revocation, TokenInfo};
pub use kit::{KIT_VERSION, Kit, KitKind, default_file_name};
pub use rekey::{PendingRekey, RekeyAborted, RekeyOutcome};

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use galata_vault_client::{Api, Events, NoEvents, Progress, Warning, now};
use galata_vault_keys::{NodeKey, seal_child_key};
use galata_vault_proto::children::{ChildEntry, ChildMode};
use galata_vault_proto::codec::FormatError;
use galata_vault_proto::ids::B64;
use galata_vault_proto::path::{EnvPath, Segment};

use crate::audit::{self, AuditReport};
use crate::error::{Error, code};
use crate::state::{LocalState, ProjectState, StateStore, TreeNode};
use crate::store::{KeyName, KeyStore};
use crate::vault::{DAY, Handle};

/// How an owner reaches a server: its URL in, a typed API out.
pub type Connector = Arc<dyn Fn(&str) -> Result<Api, Error> + Send + Sync>;

/// Acknowledges that a delegation kit makes its holder the owner of the
/// node and everything beneath it: they can read, change and delete every
/// secret there, mint tokens, and rekey it away from you.
#[derive(Debug, Clone, Copy)]
pub struct GrantsSubtreeOwnership;

/// Acknowledges that a rekey retires every token in the subtree: they die
/// with the old vaults and must be minted again.
#[derive(Debug, Clone, Copy)]
pub struct RetiresAllTokens;

/// A project, as initialised.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProjectInfo {
    /// The project's path.
    pub path: EnvPath,
    /// Its pinned server.
    pub server: String,
    /// Its root vault's id (hex).
    pub vault_id: String,
}

/// What rediscovery found below a node.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Discovery {
    /// Where it started.
    pub root: EnvPath,
    /// Every known path at or below the root, sorted.
    pub found: Vec<EnvPath>,
    /// Nodes whose vault could not be opened; kept in the tree so they can
    /// be repaired.
    pub unreachable: Vec<EnvPath>,
}

/// What removing an environment did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Removal {
    /// Every environment deleted, deepest first.
    pub deleted: Vec<EnvPath>,
    /// The parent whose key is not held here, so its children record still
    /// lists the removed environment.
    pub parent_not_updated: Option<EnvPath>,
}

/// What repairing an environment did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Repair {
    /// Whether its vault was re-created at the same vault id (it had
    /// expired); its records did not survive.
    pub created: bool,
    /// How many known child environments its children record lists again.
    pub children: usize,
    /// Rekeyed children whose sealed key was only in the lost record: import
    /// their kits to reach them again.
    pub lost: Vec<EnvPath>,
}

/// A project owner's view: the key tree, and every operation on it.
pub struct Owner {
    keys: Arc<dyn KeyStore>,
    store: Arc<dyn StateStore>,
    events: Arc<dyn Events>,
    connect: Connector,
    apis: HashMap<String, Api>,
    state: LocalState,
}

impl std::fmt::Debug for Owner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Owner")
            .field("projects", &self.state.projects.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

fn default_connector() -> Connector {
    #[cfg(feature = "http")]
    {
        Arc::new(|server: &str| {
            galata_vault_client::ClientBuilder::new(server)
                .build()
                .map_err(Error::build)
        })
    }
    #[cfg(not(feature = "http"))]
    {
        Arc::new(|server: &str| {
            Err(Error::other(format!(
                "no transport to reach {server}: build galata-vault with the `http` feature, or give the owner a connector"
            )))
        })
    }
}

fn chain_end(chain: Vec<(EnvPath, NodeKey)>) -> Result<NodeKey, Error> {
    chain
        .into_iter()
        .last()
        .map(|(_, k)| k)
        .ok_or_else(|| Error::other("a key chain includes its target"))
}

fn children_error(e: impl std::fmt::Display) -> Error {
    Error::other(e.to_string())
}

/// Whether `vault`'s server announced an expiry at its last status.
fn announces_expiry(vault: &Handle) -> bool {
    vault.status().is_some_and(|s| s.expires_at.is_some())
}

/// Whether `vault`'s server expires vaults for inactivity: its capabilities
/// give an idle window, or its latest status for the vault named an expiry
/// time (all a server older than the capabilities document can say).
fn server_expires(api: &Api, vault: &Handle) -> bool {
    let announced = matches!(
        api.capabilities(),
        Ok(Some(caps)) if caps.idle_expiry_days.is_some()
    );
    announced || announces_expiry(vault)
}

fn levenshtein(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut prev = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cur = row[j + 1];
            row[j + 1] = (prev + usize::from(ca != *cb)).min(row[j] + 1).min(cur + 1);
            prev = cur;
        }
    }
    row[b.len()]
}

/// The closest candidate, if any is plausibly a typo of `target`.
fn closest<'a>(target: &str, candidates: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    let limit = (target.len() / 3).max(2);
    candidates
        .into_iter()
        .map(|c| (levenshtein(target, c), c))
        .filter(|(d, _)| *d <= limit)
        .min()
        .map(|(_, c)| c)
}

impl Owner {
    /// An owner over `keys` and `store`, reaching servers over HTTP (feature
    /// `http`) and dropping notices. The state is loaded now.
    pub fn open(keys: Arc<dyn KeyStore>, store: Arc<dyn StateStore>) -> Result<Owner, Error> {
        let state = store.load().map_err(Error::store)?;
        Ok(Owner {
            keys,
            store,
            events: Arc::new(NoEvents),
            connect: default_connector(),
            apis: HashMap::new(),
            state,
        })
    }

    /// Send expiry, progress and warnings to `events`.
    pub fn with_events(mut self, events: Arc<dyn Events>) -> Owner {
        self.events = events;
        self.apis.clear();
        self
    }

    /// Reach each server through `connect` (a proxy, a private CA, a test
    /// transport, …). The owner's observer is attached to what it returns.
    pub fn with_connector(
        mut self,
        connect: impl Fn(&str) -> Result<Api, Error> + Send + Sync + 'static,
    ) -> Owner {
        self.connect = Arc::new(connect);
        self.apis.clear();
        self
    }

    /// The observer notices go to.
    pub fn events(&self) -> &Arc<dyn Events> {
        &self.events
    }

    /// The local state as this owner holds it now.
    pub fn state(&self) -> &LocalState {
        &self.state
    }

    /// Save the local state to the store.
    pub fn save(&self) -> Result<(), Error> {
        self.store.save(&self.state).map_err(Error::store)
    }

    /// Load the local state from the store again, dropping unsaved changes.
    pub fn reload(&mut self) -> Result<(), Error> {
        self.state = self.store.load().map_err(Error::store)?;
        Ok(())
    }

    /// The API for `server`, built once per owner.
    pub fn api(&mut self, server: &str) -> Result<Api, Error> {
        if let Some(api) = self.apis.get(server) {
            return Ok(api.clone());
        }
        let api = (self.connect)(server)?.with_events(self.events.clone());
        self.apis.insert(server.to_owned(), api.clone());
        Ok(api)
    }

    fn api_for(&mut self, path: &EnvPath) -> Result<Api, Error> {
        let server = self.state.project(path)?.server.clone();
        self.api(&server)
    }

    fn held_key(&self, path: &EnvPath) -> Result<NodeKey, Error> {
        let stored = self
            .keys
            .get(&KeyName::Node(path.clone()))
            .map_err(Error::store)?
            .ok_or_else(|| {
                Error::local(
                    code::NO_KEY,
                    format!("the key for {path} is missing from the credential store"),
                )
            })?;
        NodeKey::parse(&stored).map_err(|e| match e {
            FormatError::UnknownVersion { found } => Error::other(format!(
                "the stored key for {path} carries version {found}, which this build does not know"
            )),
            _ => Error::other(format!("the stored key for {path} is damaged")),
        })
    }

    fn store_key(&self, path: &EnvPath, key: &NodeKey) -> Result<(), Error> {
        self.keys
            .set(&KeyName::Node(path.clone()), &key.encode())
            .map_err(Error::store)
    }

    // ------------------------------------------------------------ the tree

    /// The closest known path to `path`, if one is plausibly a typo of it:
    /// data for a "did you mean" hint.
    pub fn closest_known(&self, path: &EnvPath) -> Option<EnvPath> {
        let known = self.state.known_paths();
        closest(&path.to_string(), known.iter().map(String::as_str)).and_then(|s| s.parse().ok())
    }

    /// Refuse a path absent from the known tree, before any request, with
    /// the closest known path as the suggestion ([`Error::UnknownPath`]).
    pub fn require_known(&self, path: &EnvPath) -> Result<(), Error> {
        let project_known = self
            .state
            .projects
            .contains_key(path.project_name().as_str());
        if project_known && self.state.project(path)?.knows(path) {
            return Ok(());
        }
        let message = if project_known {
            format!("unknown environment {path}")
        } else {
            format!("unknown project {}", path.project_name())
        };
        Err(Error::UnknownPath {
            path: path.to_string(),
            suggestion: self.closest_known(path).map(|p| p.to_string()),
            project_known,
            message,
        })
    }

    /// The known tree of `project`: path → vault.
    pub fn tree(&self, project: &EnvPath) -> Result<&BTreeMap<String, TreeNode>, Error> {
        Ok(&self.state.project(project)?.tree)
    }

    /// The keys from the deepest held ancestor down to `path`, inclusive.
    /// Derived keys are recomputed; a sealed one is opened from its parent's
    /// owner-only children record.
    fn chain(&self, api: &Api, path: &EnvPath) -> Result<Vec<(EnvPath, NodeKey)>, Error> {
        let project = self.state.project(path)?.clone();
        let root = project.held_root_for(path).ok_or_else(|| {
            Error::local(
                code::NO_KEY,
                format!("no key is held for {path} or any node above it"),
            )
        })?;
        let mut key = self.held_key(&root)?;
        let mut here = root.clone();
        let mut out = vec![(here.clone(), key.clone())];
        for seg in &path.segments()[root.depth()..] {
            let child = here
                .child(seg.clone())
                .map_err(|e| Error::local(code::INVALID_PATH, format!("{here}/{seg}: {e}")))?;
            let sealed = project
                .tree
                .get(&child.to_string())
                .is_some_and(|n| n.sealed);
            key = if sealed {
                let parent = Handle::open_owner(api, &key, &here.to_string())?;
                let (record, _) = parent.children()?;
                let entry = record.get(seg).ok_or_else(|| {
                    Error::other(format!("{here}'s children record no longer lists {seg}"))
                })?;
                match &entry.mode {
                    ChildMode::Derived => key.child(seg),
                    ChildMode::Sealed { key_ct } => {
                        parent.owner()?.open_child_key(&key_ct.0).map_err(|e| {
                            Error::key(e, format!("{child}'s sealed key does not open"))
                        })?
                    }
                    _ => {
                        return Err(Error::unsupported(format!(
                            "{here}'s children record lists {seg} in a way this client does not know"
                        )));
                    }
                }
            } else {
                key.child(seg)
            };
            here = child;
            out.push((here.clone(), key.clone()));
        }
        Ok(out)
    }

    /// Open `path`'s vault as its owner, keeping its ancestors alive when its
    /// server expires vaults (its capabilities say so, or its responses
    /// announce an expiry). What this owner saw there before (its
    /// pins) is handed to the vault: an older descriptor, or an older
    /// version of a record, is refused. Call [`Owner::close`] when done, so
    /// what it saw is remembered.
    pub fn environment(&mut self, path: &EnvPath) -> Result<Environment, Error> {
        self.require_known(path)?;
        let api = self.api_for(path)?;
        let mut chain = self.chain(&api, path)?;
        let key = chain
            .pop()
            .map(|(_, k)| k)
            .ok_or_else(|| Error::other("a key chain includes its target"))?;
        let vault = Handle::open_owner(&api, &key, &path.to_string())?;
        let id = vault.vault_id.to_hex();
        if let Some(pins) = self.state.pins.get(&id) {
            vault.set_pins(pins.clone())?;
        }
        self.state.touched.insert(id.clone(), now());
        let ancestors: Vec<String> = chain
            .iter()
            .map(|(_, k)| k.owner().vault_id().to_hex())
            .collect();
        if server_expires(&api, &vault) {
            // Whatever the server said before, it expires vaults now: every
            // ancestor is due its keep-alive again.
            self.state.no_expiry.remove(&id);
            for a in &ancestors {
                self.state.no_expiry.remove(a);
            }
            self.keep_alive(&api, &chain);
        } else {
            // A project's vaults share its pinned server, so none of them can
            // expire either. Keeping them alive would only spend requests and
            // link the tree by timing.
            self.state.no_expiry.insert(id);
            self.state.no_expiry.extend(ancestors);
        }
        Environment::new(vault, path.clone())
    }

    /// Remember what `env` showed (its pins), to catch a server that later
    /// shows less. Saved with the next [`Owner::save`].
    pub fn remember(&mut self, env: &Environment) {
        self.state.pins.insert(env.vault_id(), env.pins());
    }

    /// Done with `env`: remember what it showed, and save the local state.
    pub fn close(&mut self, env: Environment) -> Result<(), Error> {
        self.remember(&env);
        drop(env);
        self.save()
    }

    /// Verify `env`'s audit chain from the head recorded for it, and record
    /// the new head only on success. With `earlier > 0`, up to that many
    /// rows at or below the recorded head are included, for display. Saved
    /// with the next [`Owner::save`].
    pub fn audit(&mut self, env: &Environment, earlier: usize) -> Result<AuditReport, Error> {
        audit::verify_recorded(env.handle(), &mut self.state, earlier)
    }

    /// A signed status request to each ancestor not touched in 24 hours, so
    /// a project root outlives environments that are used every day. An
    /// ancestor whose server expires nothing (no idle window in its
    /// capabilities, and no expiry at its last status) is skipped.
    fn keep_alive(&mut self, api: &Api, ancestors: &[(EnvPath, NodeKey)]) {
        let t = now();
        for (path, key) in ancestors {
            let id = key.owner().vault_id().to_hex();
            if self.state.no_expiry.contains(&id)
                || self
                    .state
                    .touched
                    .get(&id)
                    .is_some_and(|last| t - last < DAY)
            {
                continue;
            }
            match Handle::open_owner(api, key, &path.to_string()) {
                Ok(vault) => {
                    if !server_expires(api, &vault) {
                        self.state.no_expiry.insert(id.clone());
                    }
                    self.state.touched.insert(id, t);
                }
                Err(e) => self.events.warning(&Warning::KeepAliveFailed {
                    path: path.to_string(),
                    message: e.to_string(),
                }),
            }
        }
    }

    /// Rediscover the subtree under `root` from its key alone, replacing the
    /// cached subtree. A child whose vault cannot be opened is kept, with
    /// its cached descendants, so it can be repaired. Returns those.
    fn discover_from(
        &mut self,
        api: &Api,
        root: &EnvPath,
        key: NodeKey,
    ) -> Result<Vec<EnvPath>, Error> {
        let root_sealed = self
            .state
            .project(root)?
            .tree
            .get(&root.to_string())
            .is_some_and(|n| n.sealed);
        let mut found: BTreeMap<String, TreeNode> = BTreeMap::new();
        let mut unreachable: Vec<EnvPath> = Vec::new();
        let mut queue: Vec<(EnvPath, NodeKey, bool, Option<NodeKey>)> =
            vec![(root.clone(), key, root_sealed, None)];
        while let Some((path, key, sealed, parent_key)) = queue.pop() {
            let opened = match Handle::open_owner(api, &key, &path.to_string()) {
                Ok(v) => Ok((v, key.clone(), sealed)),
                Err(e) => match self.relink(api, &path, &key, parent_key.as_ref()) {
                    Some((v, held)) => Ok((v, held, true)),
                    None => Err(e),
                },
            };
            let (vault, key, sealed) = match opened {
                Ok(found) => found,
                Err(e) if &path == root => return Err(e),
                Err(e) => {
                    self.events.warning(&Warning::Unreachable {
                        path: path.to_string(),
                        message: e.to_string(),
                        vault_missing: matches!(e, Error::VaultNotFound { .. }),
                    });
                    found.insert(
                        path.to_string(),
                        TreeNode::new(key.owner().vault_id(), sealed),
                    );
                    unreachable.push(path);
                    continue;
                }
            };
            self.state.touched.insert(vault.vault_id.to_hex(), now());
            found.insert(path.to_string(), TreeNode::new(vault.vault_id, sealed));
            let (record, _) = vault.children()?;
            for entry in record.children() {
                let child = match path.child(entry.seg.clone()) {
                    Ok(c) => c,
                    Err(e) => {
                        self.events.warning(&Warning::ChildTooDeep {
                            parent: path.to_string(),
                            message: e.to_string(),
                        });
                        continue;
                    }
                };
                let next = match &entry.mode {
                    ChildMode::Derived => (child, key.child(&entry.seg), false, Some(key.clone())),
                    ChildMode::Sealed { key_ct } => {
                        match vault.owner()?.open_child_key(&key_ct.0) {
                            Ok(k) => (child, k, true, Some(key.clone())),
                            Err(e) => {
                                self.events.warning(&Warning::SealedKeyUnopenable {
                                    path: child.to_string(),
                                    message: e.to_string(),
                                });
                                continue;
                            }
                        }
                    }
                    _ => {
                        self.events.warning(&Warning::SealedKeyUnopenable {
                            path: child.to_string(),
                            message: "its children entry is in a form this client does not know; upgrade to reach it".to_owned(),
                        });
                        continue;
                    }
                };
                queue.push(next);
            }
        }
        let project = self.state.project_mut(root)?;
        project.tree.retain(|k, _| {
            let Ok(p) = k.parse::<EnvPath>() else {
                return false;
            };
            !p.starts_with(root) || unreachable.iter().any(|u| &p != u && p.starts_with(u))
        });
        project.tree.extend(found);
        Ok(unreachable)
    }

    /// A child whose entry predates a rekey (a restore rolled the parent's
    /// record back): if a key is held for the node, open the vault with it
    /// and point the parent's entry at it again.
    fn relink(
        &self,
        api: &Api,
        path: &EnvPath,
        stale: &NodeKey,
        parent_key: Option<&NodeKey>,
    ) -> Option<(Handle, NodeKey)> {
        let parent_key = parent_key?;
        let parent = path.parent()?;
        let stored = self.keys.get(&KeyName::Node(path.clone())).ok()??;
        let held = NodeKey::parse(&stored).ok()?;
        if held.owner().vault_id() == stale.owner().vault_id() {
            return None;
        }
        let vault = Handle::open_owner(api, &held, &path.to_string()).ok()?;
        let relinked = Handle::open_owner(api, parent_key, &parent.to_string())
            .and_then(|pv| pv.seal_child(path.last(), &held));
        match relinked {
            Ok(()) => self.events.progress(&Progress::Relinked {
                path: path.to_string(),
                parent: parent.to_string(),
            }),
            Err(e) => self.events.warning(&Warning::RelinkFailed {
                path: path.to_string(),
                parent: parent.to_string(),
                message: e.to_string(),
            }),
        }
        Some((vault, held))
    }

    /// Rediscover everything reachable from the keys held for `project`,
    /// replacing its known tree. Saved with the next [`Owner::save`].
    pub fn refresh(&mut self, project: &EnvPath) -> Result<(), Error> {
        let held: Vec<EnvPath> = self
            .state
            .project(project)?
            .held
            .iter()
            .filter_map(|h| h.parse().ok())
            .collect();
        if held.is_empty() {
            return Err(Error::local(
                code::NO_KEY,
                format!("no key is held for any node of {project}"),
            ));
        }
        let api = self.api_for(project)?;
        for root in held {
            let key = self.held_key(&root)?;
            self.discover_from(&api, &root, key)?;
        }
        Ok(())
    }

    /// Rediscover the subtree under `root` from its key alone: a report of
    /// what was found, including nodes that could not be opened.
    pub fn discover(&mut self, root: &EnvPath) -> Result<Discovery, Error> {
        self.require_known(root)?;
        let api = self.api_for(root)?;
        let key = chain_end(self.chain(&api, root)?)?;
        let unreachable = self.discover_from(&api, root, key)?;
        let found = self.found_below(root)?;
        self.save()?;
        Ok(Discovery {
            root: root.clone(),
            found,
            unreachable,
        })
    }

    fn found_below(&self, root: &EnvPath) -> Result<Vec<EnvPath>, Error> {
        Ok(self
            .state
            .project(root)?
            .tree
            .keys()
            .filter_map(|k| k.parse::<EnvPath>().ok())
            .filter(|p| p.starts_with(root))
            .collect())
    }

    // ------------------------------------------------------------ projects

    /// Start a project: a fresh key and its recovery kit. Nothing reaches the
    /// server and nothing is stored until [`PendingInit::confirm_kit_stored`],
    /// so a dropped `PendingInit` leaves no trace.
    pub fn begin_init(&mut self, project: &str, server: &str) -> Result<PendingInit<'_>, Error> {
        let seg = Segment::new(project).map_err(|e| {
            Error::local(
                code::INVALID_PATH,
                format!("{project:?} is not a project name: {e}"),
            )
        })?;
        let path = EnvPath::project(seg);
        let server = galata_vault_proto::url::validate_server_url(server)
            .map_err(|e| Error::local(code::INVALID_SERVER, e))?;
        if self.state.projects.contains_key(project) {
            return Err(Error::local(
                code::PROJECT_EXISTS,
                format!("a project named {project} is already configured here"),
            ));
        }
        let key = NodeKey::generate();
        let kit = Kit::new(KitKind::Recovery, path.clone(), &server, &key);
        Ok(PendingInit {
            owner: self,
            path,
            server,
            key,
            kit,
        })
    }

    /// Create the environment `path` below a known parent whose key is
    /// reachable. Idempotent on the server: a vault left by an interrupted
    /// add is registered. Saves the local state.
    pub fn env_add(&mut self, path: &EnvPath) -> Result<(), Error> {
        let Some(parent) = path.parent() else {
            return Err(Error::local(
                code::IS_PROJECT,
                format!("{path} is a project"),
            ));
        };
        self.require_known(&parent)?;
        if self.state.project(path)?.knows(path) {
            return Err(Error::local(
                code::ENV_EXISTS,
                format!("{path} already exists"),
            ));
        }
        let api = self.api_for(path)?;
        let chain = self.chain(&api, &parent)?;
        let Some((_, parent_key)) = chain.last().cloned() else {
            return Err(Error::other("a key chain includes its target"));
        };
        self.keep_alive(&api, &chain[..chain.len() - 1]);
        let parent_vault = Handle::open_owner(&api, &parent_key, &parent.to_string())?;
        let seg = path.last().clone();
        if parent_vault.children()?.0.get(&seg).is_some() {
            return Err(Error::local(
                code::ENV_EXISTS,
                format!(
                    "{path} already exists (the known tree of {} is out of date)",
                    path.project_name()
                ),
            ));
        }

        let key = parent_key.child(&seg);
        Handle::create(&api, &key, &path.to_string())?;
        parent_vault.update_children(|r| {
            if r.get(&seg).is_none() {
                r.insert(ChildEntry::new(seg.clone(), now(), ChildMode::Derived))
                    .map_err(children_error)?;
            }
            Ok(())
        })?;
        let vault_id = key.owner().vault_id();
        self.state
            .project_mut(path)?
            .tree
            .insert(path.to_string(), TreeNode::new(vault_id, false));
        self.state.touched.insert(vault_id.to_hex(), now());
        self.save()
    }

    /// Delete `path`'s vault and, with `recursive`, every environment below
    /// it, deepest first. Each deletion is reported as
    /// [`Progress::Deleted`] as it happens. Saves the local state.
    pub fn env_remove(&mut self, path: &EnvPath, recursive: bool) -> Result<Removal, Error> {
        self.require_known(path)?;
        let api = self.api_for(path)?;
        let chain = self.chain(&api, path)?;
        let Some((_, key)) = chain.last().cloned() else {
            return Err(Error::other("a key chain includes its target"));
        };
        // See children other clients may have added.
        self.discover_from(&api, path, key)?;
        let below = self.state.project(path)?.descendants(path);
        if !below.is_empty() && !recursive {
            let names: Vec<String> = below.iter().map(ToString::to_string).collect();
            return Err(Error::local(
                code::HAS_CHILDREN,
                format!("{path} has environments below it ({})", names.join(", ")),
            ));
        }

        let mut deleted = Vec::new();
        // Deepest first, so every parent still exists while its children go.
        for node in below.iter().chain(std::iter::once(path)) {
            let node_key = chain_end(self.chain(&api, node)?)?;
            match Handle::open_owner(&api, &node_key, &node.to_string()) {
                Ok(v) => {
                    v.delete_vault()?;
                    let id = v.vault_id.to_hex();
                    self.state.pins.remove(&id);
                    self.state.audit.remove(&id);
                }
                Err(e) => self.events.warning(&Warning::Unreachable {
                    path: node.to_string(),
                    message: e.to_string(),
                    vault_missing: matches!(e, Error::VaultNotFound { .. }),
                }),
            }
            let p = self.state.project_mut(node)?;
            p.tree.remove(&node.to_string());
            if let Some(i) = p.held.iter().position(|h| h == &node.to_string()) {
                p.held.remove(i);
                self.keys
                    .delete(&KeyName::Node(node.clone()))
                    .map_err(Error::store)?;
            }
            self.events.progress(&Progress::Deleted {
                path: node.to_string(),
            });
            deleted.push(node.clone());
        }

        let mut parent_not_updated = None;
        if let Some(parent) = path.parent() {
            if chain.len() >= 2 {
                let (_, parent_key) = &chain[chain.len() - 2];
                let seg = path.last().clone();
                Handle::open_owner(&api, parent_key, &parent.to_string())?.update_children(
                    |r| {
                        let _ = r.remove(&seg);
                        Ok(())
                    },
                )?;
            } else {
                parent_not_updated = Some(parent);
            }
        } else {
            self.state.projects.remove(path.project_name().as_str());
        }
        self.save()?;
        Ok(Removal {
            deleted,
            parent_not_updated,
        })
    }

    /// Re-create an expired vault at its vault id (its records did not
    /// survive expiry) and list its known children in its children record
    /// again. On a live vault only the children record is completed. Saves
    /// the local state.
    pub fn env_repair(&mut self, path: &EnvPath) -> Result<Repair, Error> {
        self.require_known(path)?;
        let api = self.api_for(path)?;
        let key = chain_end(self.chain(&api, path)?)?;
        let created = Handle::create(&api, &key, &path.to_string())?;
        let vault = Handle::open_owner(&api, &key, &path.to_string())?;
        if created {
            // A new vault at the old id: its history restarts, so what this
            // owner saw of the expired one no longer applies.
            self.state.pins.remove(&vault.vault_id.to_hex());
            self.state.audit.remove(&vault.vault_id.to_hex());
        }
        let owner_box = vault.owner()?.box_pub();

        let project = self.state.project(path)?.clone();
        let mut entries = Vec::new();
        let mut lost = Vec::new();
        for child in project.children_of(path) {
            let Some(node) = project.tree.get(&child.to_string()) else {
                continue;
            };
            let mode = if node.sealed {
                match self
                    .keys
                    .get(&KeyName::Node(child.clone()))
                    .map_err(Error::store)?
                {
                    Some(k) => {
                        let k = NodeKey::parse(&k).map_err(|_| {
                            Error::other(format!("the stored key for {child} is damaged"))
                        })?;
                        let key_ct = seal_child_key(&owner_box, &vault.vault_id, &k)
                            .map_err(|e| Error::key(e, format!("the sealed key for {child}")))?;
                        ChildMode::Sealed {
                            key_ct: B64(key_ct),
                        }
                    }
                    None => {
                        lost.push(child);
                        continue;
                    }
                }
            } else {
                ChildMode::Derived
            };
            entries.push(ChildEntry::new(child.last().clone(), now(), mode));
        }
        vault.update_children(|r| {
            for e in &entries {
                if r.get(&e.seg).is_none() {
                    r.insert(e.clone()).map_err(children_error)?;
                }
            }
            Ok(())
        })?;
        self.state.touched.insert(vault.vault_id.to_hex(), now());
        drop(vault);
        self.save()?;
        Ok(Repair {
            created,
            children: entries.len(),
            lost,
        })
    }

    /// A delegation kit for `path`: its holder owns the node and everything
    /// beneath it, and nothing above. The caller stores it; the library
    /// writes no file.
    pub fn export_kit(&mut self, path: &EnvPath, _: GrantsSubtreeOwnership) -> Result<Kit, Error> {
        self.require_known(path)?;
        let api = self.api_for(path)?;
        let key = chain_end(self.chain(&api, path)?)?;
        let server = self.state.project(path)?.server.clone();
        let kit = Kit::new(KitKind::Delegation, path.clone(), &server, &key);
        self.save()?;
        Ok(kit)
    }

    /// Register a kit's node (recovery or delegation) and rediscover its
    /// subtree from its key alone. Saves the local state.
    pub fn import(&mut self, kit: &Kit) -> Result<Discovery, Error> {
        let path = kit.path().clone();
        let key = kit.key()?;
        let name = path.project_name().to_string();
        let vault_id = key.owner().vault_id();
        let api = self.api(kit.server())?;
        let fresh = match self.state.projects.get(&name) {
            Some(p) if p.server != kit.server() => {
                return Err(Error::local(
                    code::SERVER_MISMATCH,
                    format!(
                        "the project {name} here is pinned to {}, but the kit is for {}",
                        p.server,
                        kit.server()
                    ),
                ));
            }
            Some(p) => {
                if p.tree
                    .get(&path.to_string())
                    .is_some_and(|n| n.vault_id != vault_id)
                {
                    return Err(Error::local(
                        code::SERVER_MISMATCH,
                        format!(
                            "{path} here is a different vault from the kit's (another project with the same name?)"
                        ),
                    ));
                }
                false
            }
            None => {
                self.state
                    .projects
                    .insert(name.clone(), ProjectState::new(kit.server()));
                true
            }
        };
        let unreachable = match self.discover_from(&api, &path, key.clone()) {
            Ok(u) => u,
            Err(e) => {
                if fresh {
                    self.state.projects.remove(&name);
                }
                return Err(e);
            }
        };
        self.store_key(&path, &key)?;
        let project = self.state.project_mut(&path)?;
        if !project.held.contains(&path.to_string()) {
            project.held.push(path.to_string());
        }
        let found = self.found_below(&path)?;
        self.save()?;
        Ok(Discovery {
            root: path,
            found,
            unreachable,
        })
    }

    /// Restore a project from its recovery kit (a delegation kit is
    /// refused: import it with [`Owner::import`]).
    pub fn recover(&mut self, kit: &Kit) -> Result<Discovery, Error> {
        if kit.kind() != KitKind::Recovery {
            return Err(Error::local(
                code::INVALID_KIT,
                format!("this is a delegation kit for {}", kit.path()),
            ));
        }
        self.import(kit)
    }
}

/// A project being initialised: its key exists and its recovery kit can be
/// rendered, but nothing is on the server or in the key store yet.
pub struct PendingInit<'a> {
    owner: &'a mut Owner,
    path: EnvPath,
    server: String,
    key: NodeKey,
    kit: Kit,
}

impl std::fmt::Debug for PendingInit<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingInit")
            .field("path", &self.path)
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

/// Initialisation failed. Whether the project's vault already exists on the
/// server matters: if it does, the recovery kit is the only copy of its key.
#[derive(Debug, Clone)]
pub struct InitError {
    error: Error,
    vault_created: bool,
}

impl InitError {
    /// What failed.
    pub fn error(&self) -> &Error {
        &self.error
    }

    /// Whether the vault was created before the failure (so the kit must be
    /// kept).
    pub fn vault_created(&self) -> bool {
        self.vault_created
    }

    /// The error alone.
    pub fn into_error(self) -> Error {
        self.error
    }
}

impl std::fmt::Display for InitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for InitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl From<InitError> for Error {
    fn from(e: InitError) -> Error {
        e.error
    }
}

impl PendingInit<'_> {
    /// The project's path.
    pub fn path(&self) -> &EnvPath {
        &self.path
    }

    /// The pinned server.
    pub fn server(&self) -> &str {
        &self.server
    }

    /// The recovery kit: the only way to recover the project. Store it
    /// before confirming.
    pub fn recovery_kit(&self) -> &Kit {
        &self.kit
    }

    /// The kit is stored safely: create the project's vault (proof of work,
    /// signed creation, an empty children record), store its key, and record
    /// the project. Saves the local state.
    pub fn confirm_kit_stored(self) -> Result<ProjectInfo, InitError> {
        let PendingInit {
            owner,
            path,
            server,
            key,
            kit: _,
        } = self;
        let before = |error| InitError {
            error,
            vault_created: false,
        };
        let after = |error| InitError {
            error,
            vault_created: true,
        };
        let api = owner.api(&server).map_err(before)?;
        let created = Handle::create(&api, &key, &path.to_string()).map_err(before)?;
        if !created {
            return Err(before(Error::local(
                code::VAULT_EXISTS,
                "the server already has a vault for this key; nothing was changed",
            )));
        }
        owner.store_key(&path, &key).map_err(after)?;
        let vault_id = key.owner().vault_id();
        let mut project = ProjectState::new(server.clone());
        project.held.push(path.to_string());
        project
            .tree
            .insert(path.to_string(), TreeNode::new(vault_id, false));
        owner.state.projects.insert(path.to_string(), project);
        owner.state.touched.insert(vault_id.to_hex(), now());
        owner.save().map_err(after)?;
        Ok(ProjectInfo {
            path,
            server,
            vault_id: vault_id.to_hex(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggestions() {
        let known = ["acme", "acme/prod", "acme/dev", "acme/staging"];
        assert_eq!(closest("acme/prdo", known), Some("acme/prod"));
        assert_eq!(closest("acme/stagin", known), Some("acme/staging"));
        assert_eq!(closest("zzzz/qqqq", known), None);
    }
}
