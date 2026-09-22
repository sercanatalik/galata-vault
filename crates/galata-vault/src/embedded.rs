//! The in-process backend (feature `embedded`): the server's rules inside
//! this process, over a data directory, with no server to run.
//!
//! [`open`] takes a data directory with the layout `gv-server local` uses
//! (`vault.db` and a file journal under `journal-root/`, mode 0700), locks
//! it, replays its journal, and returns an [`Embedded`] transport. Give it to
//! [`Api::new`](crate::client::Api::new), and everything the SDK does over
//! HTTP it does in-process, through `galata-vault-server-core`. Every request is signed
//! exactly as it would be for HTTP, and the core authenticates it, checks its
//! scope and the read allow-list, applies the quotas and preconditions,
//! audits it, and journals what is critical. There is no socket, no HTTP,
//! no async runtime, no signal handler, and no output.
//!
//! ```no_run
//! use galata_vault::client::Api;
//! use galata_vault::embedded;
//!
//! let api = Api::new(embedded::open("/var/lib/my-app/vaults")?);
//! let vault = galata_vault::Vault::with_api("gvt1_…", &api)?;
//! # Ok::<(), galata_vault::Error>(())
//! ```
//!
//! The owner API reaches it through a connector:
//! `Owner::with_connector(move |_server| Ok(api.clone()))`. Pin such a
//! project to `http://127.0.0.1:8750`, the address `gv-server local` serves
//! a data directory on, and the same project can later move to a local
//! server on the same directory without a change.
//!
//! # When to use it
//!
//! * A single-process application, a test, or a tool that should work with
//!   no server running.
//! * Not a fleet. A data directory has one opener at a time: a second
//!   [`open`], in this process or another, and a `gv-server local` on the
//!   same directory, are refused with `data_dir_in_use`. Several processes
//!   share vaults by running `gv-server local` and talking to it over HTTP.
//!   A directory written through here can be served by `gv-server local`
//!   once it is closed, and the other way round.
//!
//! The policy is the default one: no proof of work, no request budget, and
//! no vault ever expires for inactivity.
//!
//! # What it does not protect against
//!
//! The embedding process can open `vault.db` and change it directly, around
//! the core. Scopes, the read allow-list, quotas and audit rows bind only
//! what goes through [`Embedded`]; the same is true of any process that runs
//! as the same user as a `gv-server local`. What still binds the embedding
//! process is the cryptography the SDK checks on every read:
//!
//! * the vault's owner key is verified against the vault id the caller
//!   holds, in its token or key;
//! * descriptors, bundles and every record are verified against owner-signed
//!   keys, so a record the embedding process forged or edited is an
//!   integrity error, never a value;
//! * values open only with keys the caller holds;
//! * [`Vault::verify_audit`](crate::Vault::verify_audit) detects a rewritten
//!   or rolled-back audit chain from a head the caller kept.
//!
//! A process with the file can still withhold or delete what it holds.

use std::path::Path;
use std::sync::Arc;

use crate::backend::{SqliteStore, StoreConfig};
use crate::client::{Request, Response, Transport, TransportError};
use crate::server_core::data_dir::{DataDir, DataDirError};
use crate::server_core::{CanonicalRequest, Core, FileJournal, Policy, SystemClock};

use crate::error::{Error, code};

/// A data directory open in this process: a [`Transport`] that serves every
/// request from `galata-vault-server-core`. Dropping it (and every `Api` sharing it)
/// closes the directory for the next opener.
pub struct Embedded {
    core: Core,
    data: DataDir,
}

impl std::fmt::Debug for Embedded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Embedded")
            .field("data_dir", &self.data.path())
            .finish_non_exhaustive()
    }
}

/// Open `data_dir`, creating it with mode 0700 if it does not exist, and
/// replay its journal. Refused with `data_dir_in_use` while another opener
/// has it, and with `invalid_data_dir` when it is not a directory, its group
/// or others can reach it, or (outside Unix) its permissions cannot be
/// checked.
pub fn open(data_dir: impl AsRef<Path>) -> Result<Embedded, Error> {
    let data = DataDir::open(data_dir.as_ref()).map_err(|e| match e {
        DataDirError::InUse(_) => Error::local(code::DATA_DIR_IN_USE, e.to_string()),
        DataDirError::Unusable(_) => Error::local(code::INVALID_DATA_DIR, e.to_string()),
    })?;
    let database = data.database();
    let store = SqliteStore::open(StoreConfig::new(&database))
        .map_err(|e| Error::other(format!("opening {}: {e}", database.display())))?;
    let journal = FileJournal::open(data.journal_root()).map_err(Error::other)?;
    let core = Core::open(
        Arc::new(store),
        Arc::new(journal),
        Policy::default(),
        Arc::new(SystemClock),
    )
    .map_err(|e| Error::other(format!("{}: {e}", data.path().display())))?;
    Ok(Embedded { core, data })
}

impl Embedded {
    /// The data directory this transport holds.
    pub fn data_dir(&self) -> &Path {
        self.data.path()
    }
}

impl Transport for Embedded {
    /// The canonical request, handed to the core as it would arrive over
    /// HTTP; the answer, with the headers the protocol reads. Nothing here
    /// can fail to answer.
    fn send(&self, request: Request<'_>) -> Result<Response, TransportError> {
        let answer = self.core.call(CanonicalRequest {
            method: request.method.as_str(),
            path_and_query: request.path_and_query,
            authorization: request.authorization,
            if_match: request.if_match,
            if_none_match: request.if_none_match,
            body: request.body.unwrap_or(&[]),
        });
        let mut response = Response::new(answer.status, answer.body);
        if let Some(version) = answer.etag {
            response = response.with_etag(format!("\"{version}\""));
        }
        if let Some(at) = answer.expires_at {
            response = response.with_expires_at(at.to_string());
        }
        Ok(response)
    }
}
