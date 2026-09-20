//! Which server URLs a client accepts: `https://`, or plain `http://` to a
//! loopback address only. Shared by `gv` and `gv-mcp`, so the rule exists once.

/// Returns the URL without a trailing slash, or why it is refused.
pub fn validate_server_url(url: &str) -> Result<String, String> {
    let url = url.trim_end_matches('/');
    let rest = if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else if let Some(rest) = url.strip_prefix("http://") {
        let host = if let Some(bracketed) = rest.strip_prefix('[') {
            bracketed.split(']').next().unwrap_or("")
        } else {
            rest.split(['/', ':']).next().unwrap_or("")
        };
        if !matches!(host, "127.0.0.1" | "localhost" | "::1") {
            return Err(
                "the server URL must use https:// (plain http:// is allowed only for loopback)"
                    .into(),
            );
        }
        rest
    } else {
        return Err("the server URL must start with https://".into());
    };
    if rest.is_empty()
        || rest
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '@' | '?' | '#' | '"'))
    {
        return Err("the server URL must be a plain https://host[:port][/path]".into());
    }
    Ok(url.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_urls() {
        assert_eq!(
            validate_server_url("https://vault.example/").unwrap(),
            "https://vault.example"
        );
        for ok in [
            "http://127.0.0.1:8750",
            "http://localhost:1",
            "http://[::1]:1",
        ] {
            assert!(validate_server_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://vault.example",
            "http://127.0.0.1.evil.example",
            "ftp://x",
            "vault.example",
            "https://user@vault.example",
            "https://vault.example/?x=1",
            "https://",
        ] {
            assert!(validate_server_url(bad).is_err(), "{bad}");
        }
    }
}
