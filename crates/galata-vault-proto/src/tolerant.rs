//! Enum values a newer peer may send that this build does not know
//! (`docs/spec/http-api.md#7`).
//!
//! Responses are read tolerantly. A field this build does not know is
//! ignored by serde. An enum value it does not know, in a response field
//! typed [`Tolerant`], becomes [`Tolerant::Unknown`], which keeps the value's
//! wire name so it can be shown. Nothing may act on an unknown value: the
//! operations that depend on understanding one (rotation, which reseals every
//! token's bundle; minting; opening a token's bundle; audit verification)
//! refuse with `unsupported_by_client` and change nothing.
//!
//! Requests stay strict. Request bodies carry the closed enums, and the
//! server refuses a name it does not know with `invalid_request`. Stored
//! rows (the audit chain, token rows) carry the closed enums too: a server
//! only ever writes values it knows.

use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// An enum whose wire names this build can list.
pub trait Vocabulary {
    /// Whether `name` is one of this build's wire names. A value whose name
    /// this build knows, but which does not parse, is malformed, not
    /// unknown.
    fn knows(name: &str) -> bool;
}

/// A response value: one this build knows, or the name of one it does not.
///
/// Serialized, a known value is the value itself and an unknown one is its
/// name as a string. Compares equal to a `T` when it holds that value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Tolerant<T> {
    /// A value this build knows.
    Known(T),
    /// The wire name of a value this build does not know: a string enum's
    /// string, or a tagged object's `kind`. For display only.
    Unknown(String),
}

impl<T> Tolerant<T> {
    /// The value, if this build knows it.
    pub fn known(&self) -> Option<&T> {
        match self {
            Tolerant::Known(t) => Some(t),
            Tolerant::Unknown(_) => None,
        }
    }

    pub fn is_known(&self) -> bool {
        matches!(self, Tolerant::Known(_))
    }

    /// The wire name of a value this build does not know.
    pub fn unknown(&self) -> Option<&str> {
        match self {
            Tolerant::Known(_) => None,
            Tolerant::Unknown(name) => Some(name),
        }
    }
}

impl<T: Copy> Tolerant<T> {
    /// The value, if this build knows it.
    pub fn get(&self) -> Option<T> {
        self.known().copied()
    }
}

impl<T> From<T> for Tolerant<T> {
    fn from(t: T) -> Tolerant<T> {
        Tolerant::Known(t)
    }
}

impl<T: PartialEq> PartialEq<T> for Tolerant<T> {
    fn eq(&self, other: &T) -> bool {
        matches!(self, Tolerant::Known(t) if t == other)
    }
}

impl<T: std::fmt::Display> std::fmt::Display for Tolerant<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tolerant::Known(t) => t.fmt(f),
            Tolerant::Unknown(name) => write!(f, "{name} (unknown to this client)"),
        }
    }
}

impl<T: Serialize> Serialize for Tolerant<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Tolerant::Known(t) => t.serialize(s),
            Tolerant::Unknown(name) => s.serialize_str(name),
        }
    }
}

impl<'de, T: DeserializeOwned + Vocabulary> Deserialize<'de> for Tolerant<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(d)?;
        let name = match &value {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Object(m) => {
                m.get("kind").and_then(|k| k.as_str()).map(str::to_owned)
            }
            _ => None,
        };
        match (serde_json::from_value::<T>(value), name) {
            (Ok(t), _) => Ok(Tolerant::Known(t)),
            (Err(_), Some(name)) if !T::knows(&name) => Ok(Tolerant::Unknown(name)),
            (Err(e), _) => Err(D::Error::custom(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{ErrorCode, Scope};
    use crate::audit::Actor;
    use crate::ids::TokenId;

    #[test]
    fn known_values_parse_and_unknown_names_are_kept() {
        let s: Tolerant<Scope> = serde_json::from_str("\"config-write\"").unwrap();
        assert_eq!(s, Scope::ConfigWrite);
        let s: Tolerant<Scope> = serde_json::from_str("\"future\"").unwrap();
        assert_eq!(s.unknown(), Some("future"));
        assert_eq!(s.to_string(), "future (unknown to this client)");
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"future\"");

        let c: Tolerant<ErrorCode> = serde_json::from_str("\"future_conflict\"").unwrap();
        assert_eq!(c, Tolerant::Unknown("future_conflict".into()));
        let c: Tolerant<ErrorCode> = serde_json::from_str("\"not_found\"").unwrap();
        assert_eq!(c, ErrorCode::NotFound);
    }

    #[test]
    fn tagged_objects_keep_their_kind_and_malformed_known_values_fail() {
        let a: Tolerant<Actor> =
            serde_json::from_str(&format!(r#"{{"kind":"token","id":"{}"}}"#, "ab".repeat(16)))
                .unwrap();
        assert_eq!(a, Actor::Token(TokenId([0xab; 16])));
        let a: Tolerant<Actor> = serde_json::from_str(r#"{"kind":"service","id":"x"}"#).unwrap();
        assert_eq!(a.unknown(), Some("service"));
        // A known kind that does not parse is malformed, never "unknown".
        assert!(serde_json::from_str::<Tolerant<Actor>>(r#"{"kind":"token","id":"zz"}"#).is_err());
        assert!(serde_json::from_str::<Tolerant<Scope>>("7").is_err());
    }
}
