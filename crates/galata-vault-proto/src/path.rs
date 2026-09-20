//! Paths name nodes in a project's key tree: `acme`, `acme/prod`,
//! `acme/prod/eu`.
//!
//! A path never leaves the client. It is a derivation input and a display
//! name, and nothing on the server knows it exists. The rules are narrow on
//! purpose: lowercase letters, digits and `-`, so `Prod` and `prod` cannot
//! silently become two different vaults.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const MAX_DEPTH: usize = 4;
pub const MAX_SEGMENT_LEN: usize = 63;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PathError {
    #[error("a path needs at least one segment")]
    Empty,
    #[error("a path is at most {MAX_DEPTH} segments deep; this one is {depth}")]
    TooDeep { depth: usize },
    #[error("a path segment cannot be empty (check for a doubled or trailing '/')")]
    EmptySegment,
    #[error("segment {segment:?} is longer than {MAX_SEGMENT_LEN} characters")]
    SegmentTooLong { segment: String },
    #[error("segment {segment:?}: {reason}")]
    BadSegment {
        segment: String,
        reason: &'static str,
    },
}

/// One validated segment: `[a-z0-9][a-z0-9-]{0,62}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Segment(String);

impl Segment {
    pub fn new(s: &str) -> Result<Segment, PathError> {
        let bytes = s.as_bytes();
        let Some(&first) = bytes.first() else {
            return Err(PathError::EmptySegment);
        };
        if bytes.len() > MAX_SEGMENT_LEN {
            return Err(PathError::SegmentTooLong {
                segment: s.to_owned(),
            });
        }
        if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
            return Err(PathError::BadSegment {
                segment: s.to_owned(),
                reason: "must start with a lowercase letter or a digit",
            });
        }
        if !bytes
            .iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        {
            return Err(PathError::BadSegment {
                segment: s.to_owned(),
                reason: "only lowercase letters, digits and '-' are allowed",
            });
        }
        Ok(Segment(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for Segment {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Segment {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Segment::new(&s).map_err(serde::de::Error::custom)
    }
}

/// A validated path of 1 to [`MAX_DEPTH`] segments. The first segment names
/// the project.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EnvPath(Vec<Segment>);

impl EnvPath {
    pub fn parse(s: &str) -> Result<EnvPath, PathError> {
        if s.is_empty() {
            return Err(PathError::Empty);
        }
        let segments = s
            .split('/')
            .map(Segment::new)
            .collect::<Result<Vec<_>, _>>()?;
        EnvPath::from_segments(segments)
    }

    fn from_segments(segments: Vec<Segment>) -> Result<EnvPath, PathError> {
        match segments.len() {
            0 => Err(PathError::Empty),
            depth if depth > MAX_DEPTH => Err(PathError::TooDeep { depth }),
            _ => Ok(EnvPath(segments)),
        }
    }

    pub fn project(name: Segment) -> EnvPath {
        EnvPath(vec![name])
    }

    pub fn segments(&self) -> &[Segment] {
        &self.0
    }

    pub fn project_name(&self) -> &Segment {
        &self.0[0]
    }

    pub fn depth(&self) -> usize {
        self.0.len()
    }

    pub fn is_project(&self) -> bool {
        self.0.len() == 1
    }

    // The one `expect` left in galata-vault-proto: every constructor (`parse`,
    // `from_segments`, `project`, `child`, `parent`) refuses or cannot build
    // an empty path, and the field is private, so a path always has a last
    // segment. Returning an `Option` would push an impossible case onto
    // every caller.
    #[allow(clippy::expect_used)]
    pub fn last(&self) -> &Segment {
        self.0.last().expect("a path has at least one segment")
    }

    pub fn parent(&self) -> Option<EnvPath> {
        (self.0.len() > 1).then(|| EnvPath(self.0[..self.0.len() - 1].to_vec()))
    }

    pub fn child(&self, segment: Segment) -> Result<EnvPath, PathError> {
        let mut segments = self.0.clone();
        segments.push(segment);
        EnvPath::from_segments(segments)
    }

    /// True if `self` is `other` or lies beneath it.
    pub fn starts_with(&self, other: &EnvPath) -> bool {
        self.0.starts_with(&other.0)
    }
}

impl fmt::Display for EnvPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, seg) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("/")?;
            }
            f.write_str(seg.as_str())?;
        }
        Ok(())
    }
}

impl FromStr for EnvPath {
    type Err = PathError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        EnvPath::parse(s)
    }
}

impl Serialize for EnvPath {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for EnvPath {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        EnvPath::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_paths() {
        for s in [
            "acme",
            "acme/prod",
            "acme/prod/eu",
            "a/b/c/d",
            "0x/9-a",
            "acme/staging-2",
        ] {
            assert_eq!(EnvPath::parse(s).unwrap().to_string(), s);
        }
        assert!(Segment::new(&"a".repeat(63)).is_ok());
    }

    #[test]
    fn invalid_segments_name_the_rule() {
        for s in [
            "acme/Prod",
            "acme/prod_eu",
            "acme/-prod",
            "acme/pr od",
            "acme/prød",
        ] {
            assert!(
                matches!(EnvPath::parse(s), Err(PathError::BadSegment { .. })),
                "{s} was accepted"
            );
        }
        assert!(matches!(
            Segment::new(&"a".repeat(64)),
            Err(PathError::SegmentTooLong { .. })
        ));
    }

    #[test]
    fn empty_and_malformed() {
        assert_eq!(EnvPath::parse(""), Err(PathError::Empty));
        for s in ["acme/", "/acme", "acme//prod"] {
            assert_eq!(EnvPath::parse(s), Err(PathError::EmptySegment), "{s}");
        }
    }

    #[test]
    fn depth_limit() {
        assert_eq!(
            EnvPath::parse("a/b/c/d/e"),
            Err(PathError::TooDeep { depth: 5 })
        );
        let deep = EnvPath::parse("a/b/c/d").unwrap();
        assert!(deep.child(Segment::new("e").unwrap()).is_err());
    }

    #[test]
    fn tree_navigation() {
        let p = EnvPath::parse("acme/prod/eu").unwrap();
        assert_eq!(p.project_name().as_str(), "acme");
        assert_eq!(p.last().as_str(), "eu");
        assert_eq!(p.parent().unwrap().to_string(), "acme/prod");
        assert!(EnvPath::parse("acme").unwrap().parent().is_none());
        assert!(p.starts_with(&EnvPath::parse("acme").unwrap()));
        assert!(!p.starts_with(&EnvPath::parse("acme/dev").unwrap()));
    }
}
