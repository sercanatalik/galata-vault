//! One configured environment, verified at startup: a meta
//! token whose vault is verified from the vault id in the token string, and
//! whose owner-signed bundle holds the name key and nothing more.
//!
//! Every listed record is checked against the descriptor's secret writer
//! key before its name is shown, with no value key anywhere in this crate:
//! the record signature covers the ciphertext's hash, which the listing
//! carries.

use std::sync::Mutex;
use std::time::Duration;

use anyhow::bail;
use galata_vault_client::{Api, ApiError, Auth, ClientBuilder};
use galata_vault_keys::{KeyError, NameContext, NameKey, TokenKeys};
use galata_vault_proto::api::{Scope, TokenSelf, VaultStatus};
use galata_vault_proto::audit::{AuditRow, RowStop, verify_rows};
use galata_vault_proto::children::is_reserved_name;
use galata_vault_proto::descriptor::Descriptor;
use galata_vault_proto::ids::{Hash32, NameHmac, TokenId};
use galata_vault_proto::path::EnvPath;
use galata_vault_proto::record::{RecordContext, RecordKind};

use crate::config::Entry;

/// gv-mcp's request timeout (the SDK's default is 120 s).
const TIMEOUT: Duration = Duration::from_secs(60);

/// A failed request, as gv-mcp has always described it: the stable code
/// (`token_expired`, or `http_<status>`) and the server's message, or why
/// the server could not be reached. Never the token.
fn failure(e: ApiError) -> String {
    match e {
        ApiError::Transport(t) => format!("could not reach the server: {}", t.message()),
        ApiError::Refused { ref message, .. } => format!("{}: {message}", e.stable_code()),
        ApiError::Malformed { detail } => {
            format!("could not reach the server: unexpected response: {detail}")
        }
        other => format!("could not reach the server: {other}"),
    }
}

/// A secret's name and latest-version metadata. Never a value.
#[derive(Debug, Clone)]
pub struct NameInfo {
    pub name: String,
    pub hmac: NameHmac,
    pub version: u64,
    pub updated_at: i64,
    pub size: u32,
}

/// The verified view of the vault: its current descriptor, and the name key
/// of that generation.
struct View {
    descriptor: Descriptor,
    name_key: NameKey,
}

pub struct Env {
    pub path: EnvPath,
    pub token_id: TokenId,
    api: Api,
    token: TokenKeys,
    view: Mutex<View>,
}

/// Verify `/v1/tokens/self` from the vault id the token carries: the owner
/// key hashes to it, the descriptor is owner-signed for it, and the bundle
/// is owner-signed for this token as `meta` and holds only the name key.
fn verify_self(path: &EnvPath, token: &TokenKeys, me: &TokenSelf) -> anyhow::Result<View> {
    let id = token.id();
    if me.token_id != id || me.vault_id != token.vault_id() {
        bail!("{path}: token {id}: the server answered for another token or vault");
    }
    if me.scope != Scope::Meta {
        bail!(
            "{path}: token {id} has scope {}; gv-mcp accepts only meta tokens, which cannot decrypt values",
            me.scope
        );
    }
    let descriptor = me
        .descriptor
        .verify_for(&token.vault_id(), &me.owner_sign_pub)
        .map_err(|e| anyhow::anyhow!("{path}: token {id}: integrity check failed: {e}"))?;
    let bundle = token
        .open_bundle(
            &me.bundle,
            &me.owner_sign_pub,
            Scope::Meta,
            descriptor.generation,
        )
        .map_err(|e| match e {
            KeyError::Kind { .. } => anyhow::anyhow!(
                "{path}: token {id}: its bundle holds more than the name key; refusing to start"
            ),
            e => anyhow::anyhow!("{path}: token {id}: its bundle does not verify: {e}"),
        })?;
    let names = bundle.into_names_only().map_err(|_| {
        anyhow::anyhow!(
            "{path}: token {id}: its bundle holds more than the name key; refusing to start"
        )
    })?;
    if names.generation != descriptor.generation {
        bail!("{path}: token {id}: its bundle is for another generation");
    }
    Ok(View {
        descriptor,
        name_key: names.name_key,
    })
}

impl Env {
    /// Refuse any token that is not `meta`, any vault that does not verify
    /// from the token's vault id, and any bundle that holds more than the
    /// name key.
    pub fn open(entry: Entry) -> anyhow::Result<Env> {
        let Entry {
            path,
            server,
            token,
        } = entry;
        let id = token.id();
        // Never a proxy from the environment, and no redirects: the one
        // client implementation (galata-vault-client), which links no value crypto.
        let api = ClientBuilder::new(&server)
            .timeout(TIMEOUT)
            .build()
            .map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
        let me: TokenSelf = api
            .token_self(&token)
            .map_err(|e| anyhow::anyhow!("{path}: token {id}: {}", failure(e)))?
            .value;
        let view = verify_self(&path, &token, &me)?;
        Ok(Env {
            path,
            token_id: id,
            api,
            token,
            view: Mutex::new(view),
        })
    }

    /// An error for the agent: the path, the token id and the failure's
    /// code. Never the token.
    fn fail(&self, e: ApiError) -> String {
        format!("{}: token {}: {}", self.path, self.token_id, failure(e))
    }

    /// After a rotation: fetch and verify the new generation's view.
    fn reload(&self) -> Result<(), String> {
        let me: TokenSelf = self
            .api
            .token_self(&self.token)
            .map_err(|e| self.fail(e))?
            .value;
        let view = verify_self(&self.path, &self.token, &me).map_err(|e| format!("{e:#}"))?;
        let mut current = self.view.lock().expect("the view lock is never poisoned");
        if view.descriptor.generation < current.descriptor.generation {
            return Err(format!(
                "{}: integrity check failed: generation rollback (saw {}, the server now shows {})",
                self.path, current.descriptor.generation, view.descriptor.generation
            ));
        }
        *current = view;
        Ok(())
    }

    /// Every live user secret, sorted by name, each record's signature
    /// verified. Reserved and deleted names are left out.
    pub fn names(&self) -> Result<Vec<NameInfo>, String> {
        for attempt in 0..2 {
            match self.try_names() {
                Err(Stale) if attempt == 0 => self.reload()?,
                Err(Stale) => {
                    return Err(format!(
                        "{}: the vault's generation keeps changing; try again",
                        self.path
                    ));
                }
                Ok(result) => return result,
            }
        }
        unreachable!("the loop returns")
    }

    fn try_names(&self) -> Result<Result<Vec<NameInfo>, String>, Stale> {
        let view = self.view.lock().expect("the view lock is never poisoned");
        let d = &view.descriptor;
        let mut out = Vec::new();
        let mut after: Option<NameHmac> = None;
        loop {
            let page =
                match self
                    .api
                    .list(Auth::Token(&self.token), RecordKind::Secret, after.as_ref())
                {
                    Ok(p) => p.value,
                    Err(e) => return Ok(Err(self.fail(e))),
                };
            for item in page.items {
                if item.generation != d.generation {
                    return Err(Stale);
                }
                let ctx = RecordContext {
                    vault_id: d.vault_id,
                    generation: item.generation,
                    kind: RecordKind::Secret,
                    name_index: item.name_hmac,
                    version: item.version,
                    written_at: item.written_at,
                    tombstone: item.tombstone,
                    value_ct_hash: item.value_ct_hash,
                    name_ct_hash: Hash32::sha256(&item.name_ct.0),
                };
                if let Err(e) = ctx.verify(&d.secret_writer_pub, &item.sig) {
                    return Ok(Err(format!(
                        "{}: integrity check failed on a listed record: {e}",
                        self.path
                    )));
                }
                if item.tombstone {
                    continue;
                }
                let name_ctx = NameContext {
                    vault_id: d.vault_id,
                    generation: d.generation,
                    kind: RecordKind::Secret,
                };
                let name =
                    match view
                        .name_key
                        .open_name(&name_ctx, &item.name_hmac, &item.name_ct.0)
                    {
                        Ok(n) => n,
                        Err(e) => {
                            return Ok(Err(format!(
                                "{}: a secret name does not decrypt: {e}",
                                self.path
                            )));
                        }
                    };
                if is_reserved_name(&name) {
                    continue;
                }
                out.push(NameInfo {
                    name,
                    hmac: item.name_hmac,
                    version: item.version,
                    updated_at: item.written_at,
                    size: item.size,
                });
            }
            match page.next_cursor {
                Some(c) => after = Some(c),
                None => break,
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Ok(out))
    }

    /// The whole hot audit chain, verified from the first row served
    /// (`docs/spec/audit.md#5`). The verdict is `Ok(None)` when every row
    /// verified, `Ok(Some(note))` when the chain continues in a row format
    /// this build does not know (those rows are unverified, not tampered),
    /// and `Err` on a failure.
    pub fn audit(&self) -> Result<(Vec<AuditRow>, AuditVerdict), String> {
        let mut rows = Vec::new();
        let mut after = 0;
        let (head, stop) = loop {
            let page = self
                .api
                .audit(Auth::Token(&self.token), after)
                .map_err(|e| self.fail(e))?
                .value;
            let n = page.rows.len();
            if let Some(last) = page.rows.last() {
                after = last.seq;
            }
            rows.extend(page.rows);
            if page.stop.is_some() || n < galata_vault_client::AUDIT_PAGE {
                break (page.head, page.stop);
            }
        };
        let verdict = match verify_rows(None, &rows, head.as_ref(), stop.as_ref()) {
            Ok(verified) => Ok(verified.unverifiable.map(|stop| match stop {
                RowStop::NewerFormat { seq, v } => format!(
                    "the rows from seq {} on are in audit row format {v}, newer than this gv-mcp \
                     reads: they are unverified, not tampered. Upgrade gv-mcp to verify them.",
                    seq.map_or_else(|| "?".to_owned(), |s| s.to_string())
                ),
                other => format!("verification stopped early: {other:?}"),
            })),
            Err(e) => Err(e.to_string()),
        };
        Ok((rows, verdict))
    }

    /// The vault's status, its descriptor verified from the pinned vault id.
    pub fn status(&self) -> Result<(VaultStatus, TokenSelf), String> {
        let status: VaultStatus = self
            .api
            .status(Auth::Token(&self.token))
            .map_err(|e| self.fail(e))?
            .value;
        status
            .descriptor
            .verify_for(&self.token.vault_id(), &status.owner_sign_pub)
            .map_err(|e| format!("{}: integrity check failed: {e}", self.path))?;
        let me = self
            .api
            .token_self(&self.token)
            .map_err(|e| self.fail(e))?
            .value;
        Ok((status, me))
    }
}

/// How an audit verification went: `Ok(None)` verified, `Ok(Some(note))`
/// verified up to rows in a newer format, `Err` failed.
pub type AuditVerdict = Result<Option<String>, String>;

/// A listing met a generation this view does not have the key for.
struct Stale;
