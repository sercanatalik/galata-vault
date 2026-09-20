//! Request signatures: one scheme for owners and tokens,
//! the canonical signing input and the `Authorization: GV-Sig …` header.
//!
//! No credential that decrypts anything crosses the wire. The caller signs
//!
//! ```text
//! gv/v1/sig \n actor \n METHOD \n path?query \n hex(sha256(body)) \n hex(vault_id)
//!           \n ts \n b64url(nonce) \n if-match \n if-none-match
//! ```
//!
//! with the node's owner key (`actor = owner`) or the token's token-auth key
//! (`actor = token:<hex id>`). An absent precondition is an empty line. The
//! server verifies against the stored `owner_sign_pub` or `token_auth_pub`,
//! checks the skew, and spends the nonce. Signing lives with the keys
//! (`galata-vault-keys`); this module only defines the bytes both sides agree on.

use crate::FormatError;
use crate::frame::label;
use crate::ids::{B64, Hash32, TokenId, VaultId};

pub const SCHEME: &str = "GV-Sig";
/// The only accepted `v=`.
pub const SIG_VERSION: &str = "1";
/// Accepted distance between the request's timestamp and server time.
pub const MAX_SKEW_SECS: i64 = 300;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SigError {
    #[error("not a GV-Sig authorization header")]
    NotGvSig,
    #[error("unsupported GV-Sig version (v=1 only)")]
    Version,
    #[error("GV-Sig parameter {0} is missing")]
    Missing(&'static str),
    #[error("GV-Sig parameter {0} appears more than once")]
    Duplicate(String),
    #[error("GV-Sig parameter {0} is not recognised")]
    Unknown(String),
    #[error("GV-Sig parameter {0} is malformed")]
    Malformed(&'static str),
}

/// Who signed: the vault's owner, or one of its tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SigActor {
    Owner,
    Token(TokenId),
}

impl std::fmt::Display for SigActor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigActor::Owner => f.write_str("owner"),
            SigActor::Token(id) => write!(f, "token:{}", id.to_hex()),
        }
    }
}

/// The request a signature covers, besides the credential and nonce.
#[derive(Debug, Clone, Copy)]
pub struct SignedRequest<'a> {
    pub method: &'a str,
    pub path_and_query: &'a str,
    pub body: &'a [u8],
    /// The `If-Match` value, if any.
    pub if_match: Option<&'a str>,
    /// The `If-None-Match` value, if any.
    pub if_none_match: Option<&'a str>,
}

impl<'a> SignedRequest<'a> {
    /// A request with no preconditions.
    pub fn new(method: &'a str, path_and_query: &'a str, body: &'a [u8]) -> SignedRequest<'a> {
        SignedRequest {
            method,
            path_and_query,
            body,
            if_match: None,
            if_none_match: None,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SigParams {
    pub actor: SigActor,
    pub vault_id: VaultId,
    pub ts: i64,
    pub nonce: [u8; 16],
    pub sig: [u8; 64],
}

impl std::fmt::Debug for SigParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigParams")
            .field("actor", &self.actor)
            .field("vault_id", &self.vault_id)
            .field("ts", &self.ts)
            .finish_non_exhaustive()
    }
}

/// The exact bytes an owner or token signs.
pub fn signing_input(
    actor: &SigActor,
    vault_id: &VaultId,
    ts: i64,
    nonce: &[u8; 16],
    request: &SignedRequest<'_>,
) -> Vec<u8> {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        label::SIG,
        actor,
        request.method.to_ascii_uppercase(),
        request.path_and_query,
        Hash32::sha256(request.body).to_hex(),
        vault_id.to_hex(),
        ts,
        B64::encode_str(nonce),
        request.if_match.unwrap_or(""),
        request.if_none_match.unwrap_or(""),
    )
    .into_bytes()
}

impl SigParams {
    /// This signature's input for `request`.
    pub fn signing_input(&self, request: &SignedRequest<'_>) -> Vec<u8> {
        signing_input(&self.actor, &self.vault_id, self.ts, &self.nonce, request)
    }

    pub fn to_header_value(&self) -> String {
        let actor = match self.actor {
            SigActor::Owner => "actor=owner".to_owned(),
            SigActor::Token(id) => format!("actor=token,token={}", id.to_hex()),
        };
        format!(
            "{SCHEME} v={SIG_VERSION},{actor},vault={},ts={},nonce={},sig={}",
            self.vault_id.to_hex(),
            self.ts,
            B64::encode_str(&self.nonce),
            B64::encode_str(&self.sig),
        )
    }

    pub fn parse(header: &str) -> Result<SigParams, SigError> {
        let rest = header
            .strip_prefix(SCHEME)
            .and_then(|r| r.strip_prefix(' '))
            .ok_or(SigError::NotGvSig)?;
        let (mut v, mut actor, mut token, mut vault, mut ts, mut nonce, mut sig) =
            (None, None, None, None, None, None, None);
        for part in rest.split(',') {
            let (k, val) = part
                .trim()
                .split_once('=')
                .ok_or(SigError::Malformed("parameter"))?;
            let slot = match k {
                "v" => &mut v,
                "actor" => &mut actor,
                "token" => &mut token,
                "vault" => &mut vault,
                "ts" => &mut ts,
                "nonce" => &mut nonce,
                "sig" => &mut sig,
                other => return Err(SigError::Unknown(other.to_owned())),
            };
            if slot.replace(val).is_some() {
                return Err(SigError::Duplicate(k.to_owned()));
            }
        }
        if v.ok_or(SigError::Missing("v"))? != SIG_VERSION {
            return Err(SigError::Version);
        }
        let actor = match (actor.ok_or(SigError::Missing("actor"))?, token) {
            ("owner", None) => SigActor::Owner,
            ("token", Some(id)) => {
                SigActor::Token(TokenId::from_hex(id).map_err(|_| SigError::Malformed("token"))?)
            }
            ("token", None) => return Err(SigError::Missing("token")),
            ("owner", Some(_)) => return Err(SigError::Unknown("token".to_owned())),
            _ => return Err(SigError::Malformed("actor")),
        };
        let vault_id = VaultId::from_hex(vault.ok_or(SigError::Missing("vault"))?)
            .map_err(|_| SigError::Malformed("vault"))?;
        let ts = ts
            .ok_or(SigError::Missing("ts"))?
            .parse::<i64>()
            .map_err(|_| SigError::Malformed("ts"))?;
        let nonce = decode_fixed::<16>(nonce.ok_or(SigError::Missing("nonce"))?)
            .map_err(|_| SigError::Malformed("nonce"))?;
        let sig = decode_fixed::<64>(sig.ok_or(SigError::Missing("sig"))?)
            .map_err(|_| SigError::Malformed("sig"))?;
        Ok(SigParams {
            actor,
            vault_id,
            ts,
            nonce,
            sig,
        })
    }
}

fn decode_fixed<const N: usize>(s: &str) -> Result<[u8; N], FormatError> {
    B64::decode_str(s)?
        .try_into()
        .map_err(|_| FormatError::Base64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(actor: SigActor) -> SigParams {
        SigParams {
            actor,
            vault_id: VaultId([0x11; 16]),
            ts: 1_757_500_000,
            nonce: [0x22; 16],
            sig: [0x33; 64],
        }
    }

    #[test]
    fn header_roundtrip_for_owners_and_tokens() {
        for actor in [SigActor::Owner, SigActor::Token(TokenId([0x44; 16]))] {
            let p = params(actor);
            let header = p.to_header_value();
            assert!(header.starts_with("GV-Sig v=1,actor="), "{header}");
            assert_eq!(SigParams::parse(&header).unwrap(), p);
        }
    }

    #[test]
    fn strict_parsing() {
        let good = params(SigActor::Owner).to_header_value();
        assert_eq!(
            SigParams::parse(&good.replace("v=1", "v=2")),
            Err(SigError::Version)
        );
        assert_eq!(SigParams::parse("Bearer gvt1_abc"), Err(SigError::NotGvSig));
        assert_eq!(
            SigParams::parse(&format!("{good},ts=5")),
            Err(SigError::Duplicate("ts".into()))
        );
        assert_eq!(
            SigParams::parse(&format!("{good},extra=1")),
            Err(SigError::Unknown("extra".into()))
        );
        let no_sig = good.split(",sig=").next().unwrap();
        assert_eq!(SigParams::parse(no_sig), Err(SigError::Missing("sig")));
        let token_header = params(SigActor::Token(TokenId([1; 16]))).to_header_value();
        let without_id = token_header.replace(&format!(",token={}", "01".repeat(16)), "");
        assert_eq!(
            SigParams::parse(&without_id),
            Err(SigError::Missing("token"))
        );
    }

    #[test]
    fn signing_input_binds_every_field() {
        let p = params(SigActor::Owner);
        let req = SignedRequest::new("put", "/v1/secrets/ab", b"{}");
        let base = p.signing_input(&req);
        assert!(
            std::str::from_utf8(&base)
                .unwrap()
                .starts_with("gv/v1/sig\nowner\nPUT\n")
        );
        let with = |f: &dyn Fn(&mut SignedRequest<'_>)| {
            let mut r = req;
            f(&mut r);
            p.signing_input(&r)
        };
        let token = SigParams {
            actor: SigActor::Token(TokenId([5; 16])),
            ..p.clone()
        };
        let variants = [
            with(&|r| r.method = "GET"),
            with(&|r| r.path_and_query = "/v1/secrets/ac"),
            with(&|r| r.body = b"{ }"),
            with(&|r| r.if_match = Some("3")),
            with(&|r| r.if_none_match = Some("*")),
            token.signing_input(&req),
            SigParams {
                vault_id: VaultId([0; 16]),
                ..p.clone()
            }
            .signing_input(&req),
            SigParams {
                ts: p.ts + 1,
                ..p.clone()
            }
            .signing_input(&req),
            SigParams {
                nonce: [0; 16],
                ..p.clone()
            }
            .signing_input(&req),
        ];
        for v in variants {
            assert_ne!(v, base);
        }
        // If-Match and If-None-Match are distinct lines.
        assert_ne!(
            with(&|r| r.if_match = Some("*")),
            with(&|r| r.if_none_match = Some("*"))
        );
    }
}
