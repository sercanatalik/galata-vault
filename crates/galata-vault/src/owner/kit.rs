//! Recovery and delegation kits: a node key, its path and its pinned
//! server, as a small commented TOML document.
//!
//! A recovery kit is for a project root; a delegation kit is for any node
//! and makes its holder the owner of that subtree. Kits hold a
//! `gvk1_` key; a v1 kit is refused by name, never reinterpreted. This module
//! renders and parses kits; storing one is the caller's business (`gv`
//! writes a 0600 file).

use crate::keys::NodeKey;
use crate::proto::codec::FormatError;
use crate::proto::path::EnvPath;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, code};

/// The kit format this crate writes.
pub const KIT_VERSION: u32 = 1;

/// Which kind of kit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KitKind {
    /// A project root's key: the only way to recover the project.
    Recovery,
    /// Any node's key: its holder owns that subtree.
    Delegation,
}

/// A kit. `Debug` never shows the key, and the key is zeroized on drop.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kit {
    v: u32,
    kind: KitKind,
    path: EnvPath,
    server: String,
    key: String,
}

impl std::fmt::Debug for Kit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kit")
            .field("kind", &self.kind)
            .field("path", &self.path)
            .field("server", &self.server)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl Drop for Kit {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn invalid(message: impl Into<String>) -> Error {
    Error::local(code::INVALID_KIT, message)
}

/// Why a kit does not parse.
#[derive(Debug)]
pub(crate) enum KitFault {
    /// Not TOML, or not a kit's fields.
    Syntax,
    /// A kit version this client does not know.
    Version(u32),
    /// A server URL a client may not use.
    Server(String),
    /// A key that does not parse.
    Key(FormatError),
    /// A recovery kit for a path below a project.
    NotAProject(String),
}

impl KitFault {
    fn into_error(self) -> Error {
        match self {
            KitFault::Syntax => invalid("not a valid kit file"),
            KitFault::Key(FormatError::UnknownVersion { found }) => invalid(format!(
                "the kit's key carries version {found}, which this build does not know"
            )),
            KitFault::Version(v) => invalid(format!("kit version {v} is not supported")),
            KitFault::Server(e) => Error::local(code::INVALID_SERVER, e),
            KitFault::Key(_) => invalid("the kit's key is damaged (its checksum does not match)"),
            KitFault::NotAProject(path) => {
                invalid(format!("a recovery kit is for a project, not {path}"))
            }
        }
    }
}

impl Kit {
    pub(crate) fn new(kind: KitKind, path: EnvPath, server: &str, key: &NodeKey) -> Kit {
        Kit {
            v: KIT_VERSION,
            kind,
            path,
            server: server.to_owned(),
            key: key.encode().to_string(),
        }
    }

    /// Recovery or delegation.
    pub fn kind(&self) -> KitKind {
        self.kind
    }

    /// The node the kit is for.
    pub fn path(&self) -> &EnvPath {
        &self.path
    }

    /// The server the node's project is pinned to.
    pub fn server(&self) -> &str {
        &self.server
    }

    pub(crate) fn key(&self) -> Result<NodeKey, Error> {
        NodeKey::parse(&self.key).map_err(|e| match e {
            FormatError::UnknownVersion { found } => invalid(format!(
                "the kit's key carries version {found}, which this build does not know"
            )),
            _ => invalid("the kit's key is damaged (its checksum does not match)"),
        })
    }

    /// The kit as text, headed `# galata-vault <kind> kit (v1)`.
    pub fn render(&self) -> Result<Zeroizing<String>, Error> {
        self.render_with_header("galata-vault")
    }

    /// The kit as text, with `header` naming the product in its first line
    /// (`# <header> <kind> kit (v1)`). Parsing ignores comments, so any
    /// header reads back.
    pub fn render_with_header(&self, header: &str) -> Result<Zeroizing<String>, Error> {
        let what = match self.kind {
            KitKind::Recovery => format!(
                "the project {:?} and every environment in it",
                self.path.to_string()
            ),
            KitKind::Delegation => format!("{} and everything beneath it", self.path),
        };
        let body = Zeroizing::new(
            toml::to_string(self).map_err(|_| Error::other("the kit could not be encoded"))?,
        );
        Ok(Zeroizing::new(format!(
            "# {header} {} kit (v{KIT_VERSION})\n\
             #\n\
             # Whoever holds this file owns {what}.\n\
             # There is no account and no reset: lose every copy of this key and\n\
             # the secrets are gone. Keep it offline or in a password manager,\n\
             # and never commit it.\n\
             {}",
            match self.kind {
                KitKind::Recovery => "recovery",
                KitKind::Delegation => "delegation",
            },
            body.as_str()
        )))
    }

    /// Read a kit. Errors never quote the input: it holds a key.
    pub fn parse(text: &str) -> Result<Kit, Error> {
        Kit::check(text).map_err(KitFault::into_error)
    }

    /// The checks of [`Kit::parse`], in order, naming what failed
    /// (`docs/spec/records.md#6`).
    pub(crate) fn check(text: &str) -> Result<Kit, KitFault> {
        let kit: Kit = toml::from_str(text).map_err(|_| KitFault::Syntax)?;
        if kit.v != KIT_VERSION {
            return Err(KitFault::Version(kit.v));
        }
        crate::proto::url::validate_server_url(&kit.server).map_err(KitFault::Server)?;
        NodeKey::parse(&kit.key).map_err(KitFault::Key)?;
        if kit.kind == KitKind::Recovery && !kit.path.is_project() {
            return Err(KitFault::NotAProject(kit.path.to_string()));
        }
        Ok(kit)
    }

    /// The default file name for this kit: `acme-recovery.gvkit`,
    /// `acme-dev-delegation.gvkit`.
    pub fn file_name(&self) -> String {
        default_file_name(&self.path, self.kind)
    }
}

/// The default file name for a kit of `kind` for `path`.
pub fn default_file_name(path: &EnvPath, kind: KitKind) -> String {
    let stem = path.to_string().replace('/', "-");
    match kind {
        KitKind::Recovery => format!("{stem}-recovery.gvkit"),
        KitKind::Delegation => format!("{stem}-delegation.gvkit"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kits_roundtrip_and_never_echo_keys() {
        let key = NodeKey::generate();
        let kit = Kit::new(
            KitKind::Recovery,
            "acme".parse().unwrap(),
            "https://vault.example",
            &key,
        );
        assert_eq!(kit.file_name(), "acme-recovery.gvkit");
        let text = kit.render().unwrap();
        assert!(text.starts_with("# galata-vault recovery kit (v1)"));
        assert!(text.contains("gvk1_"));
        let back = Kit::parse(&text).unwrap();
        assert_eq!(back.key().unwrap().encode(), key.encode());
        assert!(!format!("{back:?}").contains("gvk1_"));
        let branded = kit.render_with_header("acme-cloud").unwrap();
        assert!(branded.starts_with("# acme-cloud recovery kit (v1)"));
        assert!(Kit::parse(&branded).is_ok());

        // A damaged key is refused without being quoted.
        let damaged = text.replace("gvk1_", "gvk1_x");
        let err = Kit::parse(&damaged).unwrap_err().to_string();
        assert!(!err.contains("gvk1_"), "{err}");

        let bad_server = text.replace("https://vault.example", "http://evil.example");
        assert!(Kit::parse(&bad_server).is_err());
        let deep = text.replace("path = \"acme\"", "path = \"acme/dev\"");
        assert!(
            Kit::parse(&deep).is_err(),
            "a recovery kit is for a project"
        );
    }

    #[test]
    fn a_key_of_another_version_is_refused() {
        let other = crate::proto::codec::encode_checked("gvk2_", &[5u8; 32]);
        let text = format!(
            "v = 1\nkind = \"recovery\"\npath = \"acme\"\nserver = \"https://vault.example\"\nkey = \"{}\"\n",
            other.as_str()
        );
        let e = Kit::parse(&text).unwrap_err();
        assert_eq!(e.code(), code::INVALID_KIT);
        let err = e.to_string();
        assert!(err.contains("version 2"), "{err}");
        assert!(!err.contains(&other[5..]), "{err}");
        // A kit version this build does not know is refused before the key.
        let relabelled = text.replace("v = 1", "v = 2");
        let err = Kit::parse(&relabelled).unwrap_err().to_string();
        assert!(err.contains("kit version 2"), "{err}");
    }
}
