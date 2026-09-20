//! Colour on the terminal: a few roles from the site's palette, applied
//! only when the stream is a terminal and nobody asked for plain text.
//!
//! Muted for timestamps and the `gv:` prefix, accent for links, ids and
//! one-time codes, warn (copper on the site) for warnings and errors, ok
//! for "verified" and "done". Values and tokens are never painted: they
//! are for copying, and colour would only get in the way.

/// What a piece of output is. Accent and bold are used by `gv ui`'s feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "ui"), allow(dead_code))]
pub(crate) enum Role {
    Muted,
    Accent,
    Warn,
    Ok,
    Bold,
}

impl Role {
    fn code(self) -> &'static str {
        match self {
            Role::Muted => "\x1b[2m",
            Role::Accent => "\x1b[36m",
            Role::Warn => "\x1b[33m",
            Role::Ok => "\x1b[32m",
            Role::Bold => "\x1b[1m",
        }
    }
}

/// Whether to paint, decided once per stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Paint {
    on: bool,
}

impl Paint {
    /// Never paints.
    #[cfg_attr(not(feature = "ui"), allow(dead_code))]
    pub(crate) const PLAIN: Paint = Paint { on: false };

    /// Paints when the stream is a terminal, `NO_COLOR` is unset or empty
    /// (no-color.org) and `TERM` is not `dumb`.
    pub(crate) fn for_terminal(is_terminal: bool) -> Paint {
        Paint {
            on: is_terminal && wants_colour(),
        }
    }

    /// `text` in `role`, each line closed by a reset so a multi-line message
    /// paints evenly; `text` unchanged when painting is off.
    pub(crate) fn apply(self, role: Role, text: &str) -> String {
        if !self.on || text.is_empty() {
            return text.to_owned();
        }
        text.split('\n')
            .map(|line| {
                if line.is_empty() {
                    String::new()
                } else {
                    format!("{}{line}\x1b[0m", role.code())
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn wants_colour() -> bool {
    if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return false;
    }
    !matches!(std::env::var("TERM").as_deref(), Ok("dumb"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_leaves_text_alone() {
        assert_eq!(Paint::PLAIN.apply(Role::Warn, "warning: x"), "warning: x");
        assert_eq!(
            Paint::for_terminal(false).apply(Role::Ok, "verified"),
            "verified"
        );
    }

    #[test]
    fn painting_wraps_every_line() {
        let p = Paint { on: true };
        assert_eq!(p.apply(Role::Accent, "a"), "\x1b[36ma\x1b[0m");
        assert_eq!(
            p.apply(Role::Warn, "one\n\ntwo"),
            "\x1b[33mone\x1b[0m\n\n\x1b[33mtwo\x1b[0m"
        );
        assert_eq!(p.apply(Role::Bold, ""), "");
    }
}
