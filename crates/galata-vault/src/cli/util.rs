//! Small helpers: time and durations.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};

#[cfg_attr(not(feature = "ui"), allow(dead_code))]
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// `30d`, `12h`, `45m`, `90s`, or plain seconds.
pub fn parse_ttl(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let (digits, unit) = match s.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => (&s[..i], c),
        _ => (s, 's'),
    };
    let n: u64 = digits
        .parse()
        .with_context(|| format!("{s:?} is not a duration like 30d, 12h, 45m or 90s"))?;
    let unit = match unit {
        'd' => 86_400,
        'h' => 3_600,
        'm' => 60,
        's' => 1,
        _ => bail!("{s:?} is not a duration like 30d, 12h, 45m or 90s"),
    };
    n.checked_mul(unit).context("that duration is too long")
}

/// `2025-09-10 10:26Z`.
pub fn fmt_time(ts: i64) -> String {
    let (y, m, d, h, mi, _) = crate::proto::time::utc(ts);
    format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}Z")
}

/// Replace this process with `cmd`, as `gv run` and `gv mcp` do. On Unix
/// this is `exec`: the child's exit status is ours, and nothing of this
/// process (keys, values) outlives the switch. Returns only on failure.
#[cfg(unix)]
pub fn replace_process(mut cmd: std::process::Command) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    cmd.exec()
}

/// Off Unix there is no `exec`: run `cmd` to completion, then exit with its
/// status. Returns only if the child could not be started.
#[cfg(not(unix))]
pub fn replace_process(mut cmd: std::process::Command) -> std::io::Error {
    match cmd.status() {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(e) => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttls() {
        assert_eq!(parse_ttl("30d").unwrap(), 30 * 86_400);
        assert_eq!(parse_ttl("12h").unwrap(), 12 * 3600);
        assert_eq!(parse_ttl("45m").unwrap(), 45 * 60);
        assert_eq!(parse_ttl("90").unwrap(), 90);
        assert!(parse_ttl("3w").is_err());
        assert!(parse_ttl("d").is_err());
    }

    #[test]
    fn times() {
        assert_eq!(fmt_time(0), "1970-01-01 00:00Z");
        assert_eq!(fmt_time(1_757_500_000), "2025-09-10 10:26Z");
        assert_eq!(fmt_time(951_782_400), "2000-02-29 00:00Z");
    }
}
