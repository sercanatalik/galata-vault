//! Re-rooting a node: a fresh random
//! key for it, keys derived from that for everything below, fresh vaults
//! holding copies of every record, and the old vaults (with every token in
//! them) deleted. Nothing held before reaches the new subtree.
//!
//! The run is client-driven and resumable. Each step is recorded in the
//! state store before the next begins, and each is idempotent, so
//! [`Owner::rekey_resume`] finishes an interrupted rekey and
//! [`Owner::rekey_abort`] undoes one that has not yet relinked its parent.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;

use galata_vault_client::{Api, Auth, Progress, Warning, now};
use galata_vault_keys::NodeKey;
use galata_vault_proto::api::ErrorCode;
use galata_vault_proto::children::{ChildEntry, ChildMode, ChildrenRecord};
use galata_vault_proto::ids::VaultId;
use galata_vault_proto::path::{EnvPath, Segment};

use super::{Kit, KitKind, Owner, RetiresAllTokens, chain_end, children_error};
use crate::error::{Error, code};
use crate::state::{RekeyPlan, RekeyStep, TreeNode};
use crate::store::KeyName;
use crate::vault::Handle;

/// `root` followed by the relative path `rel` ("" is `root` itself).
fn node_path(root: &EnvPath, rel: &str) -> Result<EnvPath, Error> {
    if rel.is_empty() {
        return Ok(root.clone());
    }
    format!("{root}/{rel}").parse().map_err(|e| {
        Error::local(
            code::INVALID_PATH,
            format!("{root}/{rel} is not an environment path: {e}"),
        )
    })
}

fn parent_of(rel: &str) -> &str {
    rel.rsplit_once('/').map_or("", |(p, _)| p)
}

fn segment(s: &str) -> Result<Segment, Error> {
    Segment::new(s).map_err(|e| {
        Error::local(
            code::INVALID_PATH,
            format!("{s:?} is not a path segment: {e}"),
        )
    })
}

fn last_segment(rel: &str) -> Result<Segment, Error> {
    segment(rel.rsplit_once('/').map_or(rel, |(_, l)| l))
}

/// The key a node of the new subtree derives from the new root key.
fn derive(root: &NodeKey, rel: &str) -> Result<NodeKey, Error> {
    let mut key = root.clone();
    for s in rel.split('/').filter(|s| !s.is_empty()) {
        key = key.child(&segment(s)?);
    }
    Ok(key)
}

/// The nodes directly below `nodes[i]`, by segment.
fn direct_children(nodes: &[String], i: usize) -> Result<Vec<Segment>, Error> {
    nodes
        .iter()
        .filter(|r| !r.is_empty() && parent_of(r) == nodes[i])
        .map(|r| last_segment(r))
        .collect()
}

/// Open the vault for `key`, or `None` if the server no longer has it.
fn open_if_exists(api: &Api, key: &NodeKey, label: &str) -> Result<Option<Handle>, Error> {
    // The server answers `unauthorized` for a vault it does not have.
    match api.status(Auth::Owner(&key.owner())) {
        Err(e) if e.code() == Some(ErrorCode::Unauthorized) => Ok(None),
        _ => Handle::open_owner(api, key, label).map(Some),
    }
}

fn damaged() -> Error {
    Error::other("the rekey plan in local state is damaged")
}

/// A rekey planned but not started: the new key exists and its kit can be
/// rendered, but nothing is stored and nothing on the server has changed.
pub struct PendingRekey<'a> {
    owner: &'a mut Owner,
    path: EnvPath,
    old: NodeKey,
    new: NodeKey,
    kit: Kit,
    nodes: Vec<String>,
    old_ids: Vec<VaultId>,
    new_ids: Vec<VaultId>,
    remint: Vec<String>,
}

impl std::fmt::Debug for PendingRekey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRekey")
            .field("path", &self.path)
            .field("nodes", &self.nodes)
            .finish_non_exhaustive()
    }
}

/// A completed rekey.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RekeyOutcome {
    /// The re-rooted node.
    pub path: EnvPath,
    /// How many environments now live in fresh vaults.
    pub nodes: usize,
    /// The node's new vault id.
    pub new_vault_id: String,
    /// Where the caller stored the new kit; any earlier kit no longer works.
    pub kit: PathBuf,
    /// The tokens that died with the old vaults: "path  scope  id".
    pub remint: Vec<String>,
}

/// An aborted rekey: its new vaults are deleted and the old subtree is
/// unchanged. The caller deletes the unused kit it stored at `kit`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RekeyAborted {
    /// The node whose rekey was undone.
    pub path: EnvPath,
    /// Where the caller stored the now-unused kit.
    pub kit: PathBuf,
}

impl PendingRekey<'_> {
    /// The node being re-rooted.
    pub fn path(&self) -> &EnvPath {
        &self.path
    }

    /// The new kit: store it before confirming. After the rekey it is the
    /// only key to the node.
    pub fn kit(&self) -> &Kit {
        &self.kit
    }

    /// How many environments move to fresh vaults.
    pub fn nodes(&self) -> usize {
        self.nodes.len()
    }

    /// The tokens that will die with the old vaults: "path  scope  id".
    pub fn tokens(&self) -> &[String] {
        &self.remint
    }

    /// The node's new vault id (hex).
    pub fn new_vault_id(&self) -> String {
        self.new_ids
            .first()
            .map(VaultId::to_hex)
            .unwrap_or_default()
    }

    /// The new kit is stored at `location`: record the plan (and keep the old
    /// and new root keys in the key store), then run the rekey to the end.
    /// An interruption leaves the plan recorded for
    /// [`Owner::rekey_resume`] or [`Owner::rekey_abort`].
    pub fn confirm_kit_stored(self, location: impl Into<PathBuf>) -> Result<RekeyOutcome, Error> {
        let PendingRekey {
            owner,
            path,
            old,
            new,
            kit: _,
            nodes,
            old_ids,
            new_ids,
            remint,
        } = self;
        owner
            .keys
            .set(&KeyName::RekeyOld(path.clone()), &old.encode())
            .map_err(Error::store)?;
        owner
            .keys
            .set(&KeyName::RekeyNew(path.clone()), &new.encode())
            .map_err(Error::store)?;
        let plan = RekeyPlan {
            path: path.to_string(),
            kit: location.into(),
            nodes,
            old_ids,
            new_ids,
            remint,
            step: RekeyStep::Planned,
            linked: false,
        };
        owner.events.progress(&Progress::RekeyPlanned {
            path: plan.path.clone(),
            nodes: plan.nodes.len(),
            tokens: plan.remint.len(),
            kit: plan.kit.display().to_string(),
        });
        // The new key is stored, and the plan recorded, before anything
        // changes on the server: an interruption can always be resumed.
        owner.state.rekey = Some(plan.clone());
        owner.save()?;
        owner.run_rekey(plan)
    }
}

impl Owner {
    /// The rekey in progress, if one is.
    pub fn rekey_in_progress(&self) -> Option<&RekeyPlan> {
        self.state.rekey.as_ref()
    }

    /// Plan a re-root of `path`: walk the old subtree (every environment in
    /// it must be reachable), and generate the new root key and its kit.
    /// Nothing is stored and nothing changes until
    /// [`PendingRekey::confirm_kit_stored`].
    pub fn begin_rekey(
        &mut self,
        path: &EnvPath,
        _: RetiresAllTokens,
    ) -> Result<PendingRekey<'_>, Error> {
        if let Some(plan) = &self.state.rekey {
            return Err(Error::local(
                code::REKEY_IN_PROGRESS,
                format!("a rekey of {} is in progress", plan.path),
            ));
        }
        self.require_known(path)?;
        let api = self.api_for(path)?;
        let server = self.state.project(path)?.server.clone();
        let old = chain_end(self.chain(&api, path)?)?;

        // The old subtree, parents first, through its children records: a
        // rekey moves all of it or nothing.
        let mut nodes = Vec::new();
        let mut old_ids = Vec::new();
        let mut remint = Vec::new();
        let mut queue = VecDeque::from([(String::new(), old.clone())]);
        while let Some((rel, key)) = queue.pop_front() {
            let here = node_path(path, &rel)?;
            let vault = Handle::open_owner(&api, &key, &here.to_string()).map_err(|e| {
                e.context(format!(
                    "every environment below {path} must be reachable to rekey it; repair or remove {here} first"
                ))
            })?;
            for t in vault
                .status()
                .and_then(|st| st.tokens)
                .into_iter()
                .flatten()
            {
                remint.push(format!("{here}  {}  {}", t.scope, t.token_id));
            }
            let (record, _) = vault.children()?;
            for entry in record.children() {
                let child = if rel.is_empty() {
                    entry.seg.to_string()
                } else {
                    format!("{rel}/{}", entry.seg)
                };
                let child_key = match &entry.mode {
                    ChildMode::Derived => key.child(&entry.seg),
                    ChildMode::Sealed { key_ct } => {
                        key.owner().open_child_key(&key_ct.0).map_err(|e| {
                            Error::key(
                                e,
                                format!("{here}'s sealed entry for {} does not open", entry.seg),
                            )
                        })?
                    }
                    _ => {
                        return Err(Error::unsupported(format!(
                            "{here}'s children record lists {} in a way this client does not know",
                            entry.seg
                        )));
                    }
                };
                queue.push_back((child, child_key));
            }
            nodes.push(rel);
            old_ids.push(vault.vault_id);
        }

        // Random, not derived: nothing held before (the old key, or any
        // ancestor's) reaches the new subtree.
        let new = NodeKey::generate();
        let new_ids = nodes
            .iter()
            .map(|r| derive(&new, r).map(|k| k.owner().vault_id()))
            .collect::<Result<Vec<_>, Error>>()?;
        let kind = if path.is_project() {
            KitKind::Recovery
        } else {
            KitKind::Delegation
        };
        let kit = Kit::new(kind, path.clone(), &server, &new);
        Ok(PendingRekey {
            owner: self,
            path: path.clone(),
            old,
            new,
            kit,
            nodes,
            old_ids,
            new_ids,
            remint,
        })
    }

    fn plan_for(&self, path: Option<&EnvPath>) -> Result<RekeyPlan, Error> {
        let plan = self
            .state
            .rekey
            .clone()
            .ok_or_else(|| Error::local(code::NO_REKEY, "no rekey is in progress here"))?;
        if let Some(p) = path
            && p.to_string() != plan.path
        {
            return Err(Error::local(
                code::NO_REKEY,
                format!("the rekey in progress is for {}, not {p}", plan.path),
            ));
        }
        Ok(plan)
    }

    /// Finish the rekey in progress (of `path`, if given).
    pub fn rekey_resume(&mut self, path: Option<&EnvPath>) -> Result<RekeyOutcome, Error> {
        let plan = self.plan_for(path)?;
        self.run_rekey(plan)
    }

    /// Undo the rekey in progress (of `path`, if given), if its parent does
    /// not yet point at the new key: delete the new vaults and forget the
    /// plan and its keys. The old subtree was never changed.
    pub fn rekey_abort(&mut self, path: Option<&EnvPath>) -> Result<RekeyAborted, Error> {
        let plan = self.plan_for(path)?;
        self.abort_rekey(plan)
    }

    fn rekey_key(&self, name: &KeyName) -> Result<NodeKey, Error> {
        let text = self.keys.get(name).map_err(Error::store)?.ok_or_else(|| {
            Error::local(
                code::NO_KEY,
                format!("{name} is missing from the credential store"),
            )
        })?;
        NodeKey::parse(&text).map_err(|_| Error::other(format!("the stored key {name} is damaged")))
    }

    /// Record that `step` is complete, durably, before anything after it.
    fn advance(&mut self, plan: &mut RekeyPlan, step: RekeyStep) -> Result<(), Error> {
        plan.step = step;
        self.state.rekey = Some(plan.clone());
        self.save()?;
        self.events.progress(&Progress::RekeyStep {
            path: plan.path.clone(),
            step: step.as_str(),
        });
        Ok(())
    }

    /// Each node's old key, opened from the old root key down through the
    /// old children records; `None` where an ancestor's old vault is already
    /// gone.
    fn old_keys(
        &self,
        api: &Api,
        path: &EnvPath,
        plan: &RekeyPlan,
    ) -> Result<Vec<Option<NodeKey>>, Error> {
        let root = self.rekey_key(&KeyName::RekeyOld(path.clone()))?;
        let mut keys: Vec<Option<NodeKey>> = Vec::with_capacity(plan.nodes.len());
        let mut records: HashMap<usize, Option<ChildrenRecord>> = HashMap::new();
        for (i, rel) in plan.nodes.iter().enumerate() {
            let label = node_path(path, rel)?;
            let key = if rel.is_empty() {
                Some(root.clone())
            } else {
                let p = plan.nodes[..i]
                    .iter()
                    .position(|r| r == parent_of(rel))
                    .ok_or_else(damaged)?;
                match keys[p].clone() {
                    None => None,
                    Some(parent_key) => {
                        if let std::collections::hash_map::Entry::Vacant(slot) = records.entry(p) {
                            let parent_label = node_path(path, &plan.nodes[p])?.to_string();
                            let record = match open_if_exists(api, &parent_key, &parent_label)? {
                                Some(v) => Some(v.children()?.0),
                                None => None,
                            };
                            slot.insert(record);
                        }
                        match records.get(&p).and_then(Option::as_ref) {
                            None => None,
                            Some(record) => {
                                let seg = last_segment(rel)?;
                                let entry = record.get(&seg).ok_or_else(|| {
                                    Error::other(format!(
                                        "{label} is no longer listed in its old parent's children record"
                                    ))
                                })?;
                                Some(match &entry.mode {
                                    ChildMode::Derived => parent_key.child(&seg),
                                    ChildMode::Sealed { key_ct } => parent_key
                                        .owner()
                                        .open_child_key(&key_ct.0)
                                        .map_err(|e| {
                                            Error::key(
                                                e,
                                                format!("{label}'s sealed key does not open"),
                                            )
                                        })?,
                                    _ => {
                                        return Err(Error::unsupported(format!(
                                            "{label}'s old parent lists it in a way this client does not know"
                                        )));
                                    }
                                })
                            }
                        }
                    }
                }
            };
            if let Some(k) = &key
                && Some(&k.owner().vault_id()) != plan.old_ids.get(i)
            {
                return Err(Error::other(format!(
                    "{label} changed since the rekey was planned; abort the rekey"
                )));
            }
            keys.push(key);
        }
        Ok(keys)
    }

    pub(super) fn run_rekey(&mut self, mut plan: RekeyPlan) -> Result<RekeyOutcome, Error> {
        let path: EnvPath = plan
            .path
            .parse()
            .map_err(|e| Error::other(format!("the rekey plan names {:?}: {e}", plan.path)))?;
        let api = self.api_for(&path)?;
        let new = self.rekey_key(&KeyName::RekeyNew(path.clone()))?;
        let n = plan.nodes.len();
        if plan.new_ids.len() != n || plan.old_ids.len() != n || n == 0 {
            return Err(damaged());
        }
        let mut new_keys = Vec::with_capacity(n);
        let mut labels = Vec::with_capacity(n);
        for (rel, id) in plan.nodes.iter().zip(&plan.new_ids) {
            let key = derive(&new, rel)?;
            if key.owner().vault_id() != *id {
                return Err(Error::other(
                    "the rekey plan in local state does not match its stored key",
                ));
            }
            new_keys.push(key);
            labels.push(node_path(&path, rel)?.to_string());
        }

        if plan.step < RekeyStep::Created {
            // Bottom-up. Creation is idempotent: a vault made before an
            // interruption is kept.
            for i in (0..n).rev() {
                Handle::create(&api, &new_keys[i], &labels[i])?;
            }
            self.advance(&mut plan, RekeyStep::Created)?;
        }
        if plan.step < RekeyStep::Migrated {
            let old_keys = self.old_keys(&api, &path, &plan)?;
            for i in (0..n).rev() {
                let old_key = old_keys[i].as_ref().ok_or_else(|| {
                    Error::other(format!(
                        "{}'s old vault is gone before its records were copied; abort the rekey",
                        labels[i]
                    ))
                })?;
                let old_vault = Handle::open_owner(&api, old_key, &labels[i])?;
                let new_vault = Handle::open_owner(&api, &new_keys[i], &labels[i])?;
                // Idempotent: versions already copied are skipped.
                new_vault.copy_from(&old_vault)?;
                let children = direct_children(&plan.nodes, i)?;
                if !children.is_empty() {
                    new_vault.update_children(|r| {
                        for seg in &children {
                            if r.get(seg).is_none() {
                                r.insert(ChildEntry::new(seg.clone(), now(), ChildMode::Derived))
                                    .map_err(children_error)?;
                            }
                        }
                        Ok(())
                    })?;
                }
            }
            self.advance(&mut plan, RekeyStep::Migrated)?;
        }
        if plan.step < RekeyStep::Linked {
            self.link_parent(&api, &path, &new, &mut plan)?;
            self.advance(&mut plan, RekeyStep::Linked)?;
        }
        if plan.step < RekeyStep::Retired {
            // Deepest first, so every remaining old vault's ancestors still
            // exist to open its key from.
            let old_keys = self.old_keys(&api, &path, &plan)?;
            for i in (0..n).rev() {
                let Some(key) = &old_keys[i] else { continue };
                if let Some(v) = open_if_exists(&api, key, &labels[i])? {
                    v.delete_vault()?;
                }
            }
            self.advance(&mut plan, RekeyStep::Retired)?;
        }
        self.finish_rekey(&path, &plan, &new)
    }

    /// Point the parent's children entry at the new key, sealed to the
    /// parent's owner, or warn that the node is now detached.
    fn link_parent(
        &mut self,
        api: &Api,
        path: &EnvPath,
        new: &NodeKey,
        plan: &mut RekeyPlan,
    ) -> Result<(), Error> {
        let Some(parent) = path.parent() else {
            return Ok(());
        };
        if self.state.project(path)?.held_root_for(&parent).is_none() {
            self.events.warning(&Warning::Detached {
                path: path.to_string(),
                parent: parent.to_string(),
            });
            return Ok(());
        }
        let parent_key = chain_end(self.chain(api, &parent)?)?;
        Handle::open_owner(api, &parent_key, &parent.to_string())?
            .seal_child(path.last(), new)
            .map_err(|e| {
                e.context(format!(
                    "relinking {path} in {parent}'s children record; resuming the rekey retries"
                ))
            })?;
        plan.linked = true;
        Ok(())
    }

    fn finish_rekey(
        &mut self,
        path: &EnvPath,
        plan: &RekeyPlan,
        new: &NodeKey,
    ) -> Result<RekeyOutcome, Error> {
        let p = plan.path.clone();
        // The new key is random, not derived: keep it, so this machine reaches
        // the node whatever happens to its parent's record.
        self.store_key(path, new)?;
        let project = self.state.project_mut(path)?;
        // Keys held for nodes below were old ones; the new key derives them all.
        let below: Vec<String> = project
            .held
            .iter()
            .filter(|h| h.as_str() != p && h.parse::<EnvPath>().is_ok_and(|h| h.starts_with(path)))
            .cloned()
            .collect();
        project.held.retain(|h| !below.contains(h));
        if !project.held.contains(&p) {
            project.held.push(p.clone());
        }
        project
            .tree
            .retain(|k, _| !k.parse::<EnvPath>().is_ok_and(|k| k.starts_with(path)));
        for (i, (rel, id)) in plan.nodes.iter().zip(&plan.new_ids).enumerate() {
            project.tree.insert(
                node_path(path, rel)?.to_string(),
                TreeNode::new(*id, i == 0 && plan.linked),
            );
        }
        for id in &plan.old_ids {
            let h = id.to_hex();
            self.state.pins.remove(&h);
            self.state.audit.remove(&h);
            self.state.touched.remove(&h);
            self.state.no_expiry.remove(&h);
        }
        let t = now();
        for id in &plan.new_ids {
            self.state.touched.insert(id.to_hex(), t);
        }
        self.state.rekey = None;
        self.save()?;
        for h in &below {
            if let Ok(node) = h.parse::<EnvPath>() {
                self.keys
                    .delete(&KeyName::Node(node))
                    .map_err(Error::store)?;
            }
        }
        self.keys
            .delete(&KeyName::RekeyOld(path.clone()))
            .map_err(Error::store)?;
        self.keys
            .delete(&KeyName::RekeyNew(path.clone()))
            .map_err(Error::store)?;
        Ok(RekeyOutcome {
            path: path.clone(),
            nodes: plan.nodes.len(),
            new_vault_id: plan
                .new_ids
                .first()
                .map(ToString::to_string)
                .unwrap_or_default(),
            kit: plan.kit.clone(),
            remint: plan.remint.clone(),
        })
    }

    fn abort_rekey(&mut self, plan: RekeyPlan) -> Result<RekeyAborted, Error> {
        let path: EnvPath = plan
            .path
            .parse()
            .map_err(|e| Error::other(format!("the rekey plan names {:?}: {e}", plan.path)))?;
        let forward_only = || {
            Error::local(
                code::REKEY_FORWARD_ONLY,
                format!(
                    "{path}: its parent already points at the new key, so it can only go forward"
                ),
            )
        };
        if plan.linked || plan.step >= RekeyStep::Linked {
            return Err(forward_only());
        }
        let api = self.api_for(&path)?;
        let new = self.rekey_key(&KeyName::RekeyNew(path.clone()))?;
        // The link may have landed without being recorded.
        if let Some(parent) = path.parent()
            && self.state.project(&path)?.held_root_for(&parent).is_some()
        {
            let parent_key = chain_end(self.chain(&api, &parent)?)?;
            let (record, _) =
                Handle::open_owner(&api, &parent_key, &parent.to_string())?.children()?;
            if let Some(ChildMode::Sealed { key_ct }) = record.get(path.last()).map(|e| &e.mode)
                && parent_key
                    .owner()
                    .open_child_key(&key_ct.0)
                    .is_ok_and(|k| Some(&k.owner().vault_id()) == plan.new_ids.first())
            {
                return Err(forward_only());
            }
        }
        for rel in plan.nodes.iter().rev() {
            let key = derive(&new, rel)?;
            let label = node_path(&path, rel)?.to_string();
            if let Some(v) = open_if_exists(&api, &key, &label)? {
                v.delete_vault()?;
            }
        }
        self.state.rekey = None;
        self.save()?;
        self.keys
            .delete(&KeyName::RekeyOld(path.clone()))
            .map_err(Error::store)?;
        self.keys
            .delete(&KeyName::RekeyNew(path.clone()))
            .map_err(Error::store)?;
        Ok(RekeyAborted {
            path,
            kit: plan.kit,
        })
    }
}
