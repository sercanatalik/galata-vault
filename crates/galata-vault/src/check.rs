//! What the client checks before a config leaves this process: that it
//! parses in its declared format, and that it holds no credential.
//!
//! A config is readable by weaker tokens than a secret, so a key pasted into
//! a config is a key handed to every config reader. The patterns are exact,
//! with no entropy guessing: a false positive costs an explicit override,
//! while a heuristic's misses would look like a guarantee it cannot give.
//! Errors name the line and the kind of pattern, never the matched text.

use galata_vault_keys::TokenKeys;
use galata_vault_seal::ConfigFormat;

use crate::error::{Error, code};

fn line_at(bytes: &[u8], offset: usize) -> usize {
    bytes[..offset.min(bytes.len())]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
}

/// Refuse a body that is not UTF-8, or that does not parse as `toml` or
/// `json` when declared so. `yaml` and `text` are checked for UTF-8 only.
pub fn validate(format: ConfigFormat, body: &[u8]) -> Result<(), Error> {
    let text = std::str::from_utf8(body).map_err(|e| {
        Error::local(
            code::INVALID_CONFIG,
            format!(
                "line {}: the body is not UTF-8 text",
                line_at(body, e.valid_up_to())
            ),
        )
    })?;
    match format {
        ConfigFormat::Toml => toml::from_str::<toml::Table>(text)
            .map(|_| ())
            .map_err(|e| {
                let line = e.span().map_or(1, |s| line_at(body, s.start));
                Error::local(
                    code::INVALID_CONFIG,
                    format!("line {line}: the body does not parse as toml"),
                )
            }),
        ConfigFormat::Json => serde_json::from_str::<serde_json::Value>(text)
            .map(|_| ())
            .map_err(|e| {
                Error::local(
                    code::INVALID_CONFIG,
                    format!("line {}: the body does not parse as json", e.line()),
                )
            }),
        _ => Ok(()),
    }
}

/// Refuse a body holding a credential literal: a checksum-valid `gvt1_`
/// token or `gvk1_` key, a PEM private key, or `0x` and exactly 64 hex
/// digits (an EVM private key's shape).
pub fn scan_literals(body: &[u8]) -> Result<(), Error> {
    let text = String::from_utf8_lossy(body);
    for (i, line) in text.split('\n').enumerate() {
        if let Some(kind) = literal_in(line) {
            return Err(Error::local(
                code::CREDENTIAL_LITERAL,
                format!(
                    "line {}: a {kind} in a config. Config tokens can read configs, so a key \
                     here is a key for every config reader; keep it in a secret, or allow \
                     literals for this one write",
                    i + 1
                ),
            ));
        }
    }
    Ok(())
}

fn is_token(s: &str) -> bool {
    TokenKeys::parse(s).is_ok()
}

fn is_node_key(s: &str) -> bool {
    galata_vault_proto::codec::decode_node_key(s).is_ok()
}

/// A prefix, what a match is called, and the check that it is a real one.
type Pattern = (&'static str, &'static str, fn(&str) -> bool);

fn literal_in(line: &str) -> Option<&'static str> {
    if line.contains("-----BEGIN") && line.contains("PRIVATE KEY-----") {
        return Some("PEM private key");
    }
    let checks: [Pattern; 2] = [
        ("gvt1_", "galata-vault token", is_token),
        ("gvk1_", "galata-vault node key", is_node_key),
    ];
    for (prefix, kind, valid) in checks {
        let mut rest = line;
        while let Some(at) = rest.find(prefix) {
            let tail = &rest[at..];
            let run = tail[prefix.len()..]
                .find(|c: char| !c.is_ascii_alphanumeric())
                .unwrap_or(tail.len() - prefix.len());
            if valid(&tail[..prefix.len() + run]) {
                return Some(kind);
            }
            rest = &tail[prefix.len()..];
        }
    }
    let bytes = line.as_bytes();
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] != b'0' || !matches!(bytes[i + 1], b'x' | b'X') {
            continue;
        }
        if i > 0 && bytes[i - 1].is_ascii_alphanumeric() {
            continue;
        }
        let digits = bytes[i + 2..]
            .iter()
            .take_while(|b| b.is_ascii_hexdigit())
            .count();
        let after = bytes.get(i + 2 + digits);
        if digits == 64 && !after.is_some_and(u8::is_ascii_alphanumeric) {
            return Some("hex private key");
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_are_checked_and_errors_name_the_line() {
        assert!(validate(ConfigFormat::Toml, b"[a]\nb = 1\n").is_ok());
        let e = validate(ConfigFormat::Toml, b"[a]\nb = 1\nc = = 2\nsecret = \"x\"\n").unwrap_err();
        assert_eq!(e.code(), code::INVALID_CONFIG);
        assert!(e.message().starts_with("line 3:"), "{e}");
        assert!(!e.message().contains("secret"), "never the body");
        let e = validate(ConfigFormat::Json, b"{\n\"a\": 1,\n}").unwrap_err();
        assert!(e.message().starts_with("line 3:"), "{e}");
        assert!(validate(ConfigFormat::Yaml, b"a: [unclosed").is_ok());
        assert!(validate(ConfigFormat::Text, b"\xff").is_err());
    }

    #[test]
    fn literals_are_refused_by_exact_pattern() {
        let hex = "ab".repeat(32);
        let key = format!("[producer]\nagent_key = \"0x{hex}\"\n");
        let e = scan_literals(key.as_bytes()).unwrap_err();
        assert_eq!(e.code(), code::CREDENTIAL_LITERAL);
        assert!(e.message().starts_with("line 2: a hex private key"), "{e}");
        assert!(!e.message().contains(&hex), "never the match");

        // An address is 40 digits, and 65 is not a key's shape either.
        let address = format!("wallet = \"0x{}\"", "cd".repeat(20));
        assert!(scan_literals(address.as_bytes()).is_ok());
        assert!(scan_literals(format!("x = \"0x{hex}a\"").as_bytes()).is_ok());

        let pem = b"k = \"\"\"\n-----BEGIN EC PRIVATE KEY-----\n\"\"\"";
        assert!(
            scan_literals(pem)
                .unwrap_err()
                .message()
                .starts_with("line 2")
        );

        let token = TokenKeys::generate(galata_vault_proto::ids::VaultId([3; 16])).token_string();
        let line = format!("token = \"{}\"", token.as_str());
        assert!(scan_literals(line.as_bytes()).is_err());
        // A mistyped token is not a token.
        let mut bad = token.as_str().to_owned();
        bad.pop();
        bad.push('x');
        assert!(scan_literals(format!("t = \"{bad}\"").as_bytes()).is_ok());
    }
}
