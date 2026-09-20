//! The pages, as maud templates. maud escapes every interpolation, so a name
//! or a value shaped like markup renders as text; the CSP, with no inline
//! script and no inline style, is the second line. No `style` attribute
//! appears anywhere: the stylesheet has a class for everything.

use galata_vault_proto::api::{Scope, VaultStatus, VersionMeta};
use galata_vault_proto::audit::ChainHead;
use galata_vault_proto::tolerant::Tolerant;
use maud::{DOCTYPE, Markup, PreEscaped, html};
use serde_json::json;

use super::web::encode;
use crate::secrets::{actor_text, writer_text};
use crate::util::{fmt_time, now};
use galata_vault::AuditReport;
use galata_vault::Entry as Item;
use galata_vault::owner::TokenInfo as TokenRow;

pub struct RailEnv {
    pub path: String,
    pub label: String,
    pub depth: usize,
    /// Held from an environment kit, not derived from a project key.
    pub kit: bool,
    pub rekeyed: bool,
    pub vault: String,
}

pub struct RailProject {
    pub name: String,
    pub key: &'static str,
    pub root: Option<RailEnv>,
    pub envs: Vec<RailEnv>,
}

pub struct Frame {
    /// The binary's name, in the page's hints.
    pub bin: &'static str,
    pub rail: Vec<RailProject>,
    pub active: Option<String>,
    pub server: Option<String>,
    pub idle: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Cmp {
    OnlyA,
    OnlyB,
    Same,
    Differ,
}

pub struct CmpRow {
    pub name: String,
    pub a: Option<u64>,
    pub b: Option<u64>,
    pub cmp: Cmp,
}

// The tower mark, the same path as site/assets/logo.svg: filled, not stroked
// (`.mark` in the stylesheet).
const MARK: &str = r#"<svg class="mark" viewBox="0 0 64 64" aria-hidden="true"><circle cx="32" cy="4.2" r="1.6"/><path fill-rule="evenodd" d="M32 6.5L46.5 25.5H44.5V34H42V56H46V60H18V56H22V34H19.5V25.5H17.5ZM24.2 32V29.4A1.8 1.8 0 0 1 27.8 29.4V32ZM30.2 32V29.4A1.8 1.8 0 0 1 33.8 29.4V32ZM36.2 32V29.4A1.8 1.8 0 0 1 39.8 29.4V32ZM30.8 42V38.6A1.2 1.2 0 0 1 33.2 38.6V42ZM29.6 47.5A2.4 2.4 0 0 1 34.4 47.5A2.4 2.4 0 0 1 33.38 49.47L34.3 55H29.7L30.62 49.47A2.4 2.4 0 0 1 29.6 47.5Z"/></svg>"#;
// Lucide-style icons, drawn by the stylesheet's `svg` rule.
const FOLDER: &str = r#"<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.7-.9l-.8-1.2A2 2 0 0 0 7.9 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/></svg>"#;
const KEY: &str = r#"<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>"#;
const LOCK: &str = r#"<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>"#;
const LOCK_OPEN: &str = r#"<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>"#;
const MOON: &str = r#"<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>"#;
const COPY: &str = r#"<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="8" y="8" width="14" height="14" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>"#;
const EYE: &str = r#"<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>"#;
const HISTORY: &str = r#"<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l4 2"/></svg>"#;
const TRASH: &str = r#"<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>"#;
const PLUS: &str =
    r#"<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14"/><path d="M12 5v14"/></svg>"#;
const COMPARE: &str = r#"<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M13 6h3a2 2 0 0 1 2 2v7"/><path d="M11 18H8a2 2 0 0 1-2-2V9"/></svg>"#;
const RESTORE: &str = r#"<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>"#;
const CLOSE: &str = r#"<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>"#;
const ALERT: &str = r#"<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m21.7 18-8-14a2 2 0 0 0-3.5 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>"#;
const SHIELD: &str = r#"<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 13c0 5-3.5 7.5-7.7 9a1 1 0 0 1-.6 0C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.2-2.7a1.2 1.2 0 0 1 1.6 0C14.5 3.8 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></svg>"#;
const UNLINK: &str = r#"<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m18.84 12.25 1.72-1.71h-.02a5 5 0 0 0-.12-7.07 5 5 0 0 0-6.95 0l-1.72 1.71"/><path d="m5.17 11.75-1.71 1.71a5 5 0 0 0 .12 7.07 5 5 0 0 0 6.95 0l1.71-1.71"/><path d="M8 2v3"/><path d="M2 8h3"/><path d="M16 19v3"/><path d="M19 16h3"/></svg>"#;
const TERMINAL: &str = r#"<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m4 17 6-6-6-6"/><path d="M12 19h8"/></svg>"#;

const MASK: &str = "••••••••••••";

fn icon(svg: &'static str) -> PreEscaped<&'static str> {
    PreEscaped(svg)
}

/// "3 min ago", "2 h ago", "4 d ago".
fn ago(ts: i64) -> String {
    let d = (now() - ts).max(0);
    match d {
        0..60 => "just now".to_owned(),
        60..3_600 => format!("{} min ago", d / 60),
        3_600..86_400 => format!("{} h ago", d / 3_600),
        _ => format!("{} d ago", d / 86_400),
    }
}

/// A duration in words: "30 d", "12 h", "45 min".
pub fn span(secs: i64) -> String {
    match secs {
        s if s >= 86_400 => format!("{} d", s / 86_400),
        s if s >= 3_600 => format!("{} h", s / 3_600),
        s => format!("{} min", (s / 60).max(1)),
    }
}

fn until(ts: i64) -> String {
    let d = ts - now();
    if d <= 0 {
        "expired".to_owned()
    } else {
        format!("in {}", span(d))
    }
}

fn size(n: u32) -> String {
    if n < 1024 {
        format!("{n} B")
    } else {
        format!("{:.1} KB", f64::from(n) / 1024.0)
    }
}

pub fn decrypts(scope: Scope) -> &'static str {
    match scope {
        Scope::Read => "secrets",
        Scope::Admin => "secrets and configs, and writes both",
        Scope::Append => "nothing · writes secrets and configs",
        Scope::Meta => "nothing · names only",
        Scope::Config => "configs · never a secret",
        Scope::ConfigWrite => "configs, and writes them · never a secret",
        _ => "unknown to this gv",
    }
}

/// As [`decrypts`], for a scope a newer client may have minted.
fn decrypts_any(scope: &Tolerant<Scope>) -> &'static str {
    scope.get().map_or("unknown to this gv", decrypts)
}

fn env_url(env: &str, tab: &str) -> String {
    format!("/e/{env}/{tab}")
}

fn history_url(env: &str, name: &str, all: bool) -> String {
    format!(
        "/e/{env}/secrets?name={}{}",
        encode(name),
        if all { "&all=1" } else { "" }
    )
}

fn target(env: &str, name: &str, version: Option<u64>) -> String {
    json!({ "env": env, "name": name, "version": version }).to_string()
}

fn depth_class(depth: usize) -> &'static str {
    match depth {
        0..=2 => "d1",
        3 => "d2",
        _ => "d3",
    }
}

fn head(title: &str, bin: &str) -> Markup {
    html! {
        head {
            meta charset="utf-8";
            meta name="viewport" content="width=device-width, initial-scale=1";
            meta name="referrer" content="no-referrer";
            title { (title) " · " (bin) " ui" }
            link rel="stylesheet" href="/assets/app.css";
            script src="/assets/app.js" {}
        }
    }
}

fn crumb(env: &str) -> Markup {
    let (project, rest) = env.split_once('/').unwrap_or((env, ""));
    html! {
        span.muted { (project) }
        @for seg in rest.split('/').filter(|s| !s.is_empty()) {
            span.muted { "/" }
            span.b { (seg) }
        }
    }
}

fn state_card(icon_svg: &'static str, title: &str, body: &str, how: Markup) -> Markup {
    html! {
        div.card.state {
            div.state-icon { (icon(icon_svg)) }
            div.state-title { (title) }
            div.state-body { (body) }
            div.state-how { (how) }
        }
    }
}

fn enter_hint(bin: &str) -> Markup {
    html! { span.kbd { "enter" } span { "in the terminal running " (bin) " ui prints a new link" } }
}

fn standalone(bin: &str, crumb_text: &str, cards: Markup, boot: bool) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            (head(&format!("{bin} ui"), bin))
            body.gv.state-page data-boot[boot] {
                header.top {
                    div.brand { (icon(MARK)) span { "galata vault" } span.ui { "ui" } }
                    div.vsep {}
                    div.crumb { span.muted { (crumb_text) } }
                }
                main.states { (cards) }
            }
        }
    }
}

/// `/`: exchanges the link's code for a session, or explains why it can't.
pub fn boot(bin: &str) -> Markup {
    standalone(
        bin,
        "no session",
        html! {
            div data-state="boot" {
                (state_card(LOCK_OPEN, "opening your session…", "exchanging this link's one-time code for a session.", html! {}))
            }
            div data-state="used" hidden {
                (state_card(UNLINK, "this link has been used", "each link opens one session, once, and its code left the address bar as soon as it was spent. a copied link, a reopened tab or browser history lands here.", enter_hint(bin)))
            }
            div data-state="nolink" hidden {
                (state_card(TERMINAL, &format!("open the link {bin} ui printed"), &format!("this page needs the one-time link from the terminal running {bin} ui."), html! { span.cmd { (bin) " ui" } }))
            }
        },
        true,
    )
}

/// Any page asked for without a live session.
pub fn no_session(bin: &str) -> Markup {
    standalone(
        bin,
        "no session",
        state_card(
            LOCK,
            "locked",
            &format!(
                "this browser has no session. sessions end after idle, when you lock, or when the terminal prints a new link. the keys never left {bin} ui, so there was nothing here to lose."
            ),
            enter_hint(bin),
        ),
        false,
    )
}

fn overlays(bin: &str) -> Markup {
    html! {
        div.overlay data-overlay="locked" hidden {
            (state_card(LOCK, "locked", &format!("this page dropped everything it was showing, and {bin} ui ended the session."), enter_hint(bin)))
        }
        div.overlay data-overlay="stopped" hidden {
            (state_card(TERMINAL, &format!("{bin} ui has stopped"), "the process that holds your keys has exited, so this page can do nothing. the vault server may still be running, but it never decrypts.", html! { span { "start it again:" } span.cmd { (bin) " ui" } }))
        }
        div.scrim.modal data-modal="confirm" hidden {
            div.dialog {
                div {
                    div.dt data-confirm-title {}
                    div.dd { "this page can ask. only the terminal running " (bin) " ui can say yes." }
                }
                div.box.codebox {
                    span.eyebrow { "confirmation code" }
                    span.code.mono data-confirm-code {}
                    span.muted.small { "the terminal shows a code too. answer y there if it matches this one, n if it doesn't." }
                }
                div.status {
                    span.dot.amber.pulse data-confirm-dot {}
                    span.b data-confirm-state { "waiting for the terminal" }
                }
                div.box.handover data-handover-box hidden {
                    div.muted.small { "token · shown once. " (bin) " ui keeps no copy after you take it, and this page never sees it." }
                    div.row {
                        button.btn.sm.outline type="button" data-handover="copy" { (icon(COPY)) "copy" }
                        input.input.sm data-handover-path placeholder="~/token-file" autocomplete="off" spellcheck="false";
                        button.btn.sm.outline type="button" data-handover="save" { "save to file" }
                    }
                    div.muted.small { "a saved file gets mode 0600, and an existing file is never overwritten." }
                }
                div.df {
                    button.btn.sm.ghost type="button" data-close { "close" span.kbd { "esc" } }
                }
            }
        }
        div.scrim.modal data-modal="ask" hidden {
            div.dialog {
                div.dt data-ask-text {}
                div.df {
                    button.btn.sm.ghost type="button" data-close { "cancel" }
                    button.btn.sm.danger-solid type="button" data-ask-ok { "ok" }
                }
            }
        }
        div.toast data-toast hidden {}
    }
}

fn rail(f: &Frame) -> Markup {
    let on = |path: &str| f.active.as_deref() == Some(path);
    html! {
        nav.card.rail {
            div.ch { div.ct { "projects" } div.cd { "keys held on this machine" } }
            div.tree {
                @for p in &f.rail {
                    @match &p.root {
                        Some(r) => {
                            a.tr.proj.on[on(&r.path)] href=(env_url(&r.path, "secrets")) {
                                (icon(if p.key == "environment kit" { KEY } else { FOLDER }))
                                span { (p.name) }
                                span.n { (p.key) }
                            }
                        }
                        None => {
                            div.tr.proj { (icon(KEY)) span { (p.name) } span.n { (p.key) } }
                        }
                    }
                    @for e in &p.envs {
                        a.tr.env.(depth_class(e.depth)).on[on(&e.path)] href=(env_url(&e.path, "secrets")) {
                            span { (e.label) }
                            @if e.kit { span.n { "kit" } } @else if e.rekeyed { span.n { "rekeyed" } }
                        }
                    }
                }
                @if f.rail.is_empty() {
                    div.muted.small.pad { "no projects here yet: create one with " (f.bin) " init" }
                }
            }
            div.cf { a.btn.xs.outline href="/projects" { "all environments" } }
        }
    }
}

fn layout(f: &Frame, title: &str, crumb: Markup, main: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            (head(title, f.bin))
            body.gv data-app {
                header.top {
                    div.brand { (icon(MARK)) span { "galata vault" } span.ui { (f.bin) " ui" } }
                    div.vsep {}
                    div.crumb { (crumb) }
                    div.top-right {
                        @if let Some(s) = &f.server {
                            div.chip { span.dot.ok {} span.b { "server" } span.muted.mono.small { (s) } }
                        }
                        div.chip { (icon(LOCK_OPEN)) span.b { "unlocked" } span.muted { "locks after " (f.idle) " idle" } }
                        button.btn.ism.outline type="button" title="light or dark" data-theme-toggle { (icon(MOON)) }
                        button.btn.sm.outline type="button" data-lock { (icon(LOCK)) "lock" }
                    }
                }
                div.body {
                    (rail(f))
                    main.main { (main) }
                }
                (overlays(f.bin))
            }
        }
    }
}

fn env_head(env: &str, status: Option<&VaultStatus>, actions: Markup) -> Markup {
    html! {
        div.ch {
            div.ct.mono { (env) }
            div.cd {
                @if let Some(s) = status {
                    "generation " (s.generation) " · " (s.bytes_used) " of " (s.limits.max_vault_bytes) " bytes"
                    @if let Some(at) = s.expires_at {
                        " · expires " (fmt_time(at)) " unless used"
                    }
                }
            }
            div.ca { (actions) }
        }
    }
}

fn tabs(env: &str, active: &str) -> Markup {
    html! {
        nav.tabs {
            @for t in ["secrets", "tokens", "audit", "compare"] {
                a.tab.on[t == active] href=(env_url(env, t)) { (t) }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn secrets(
    f: &Frame,
    env: &str,
    items: &[Item],
    all: bool,
    history: Option<(&str, &[VersionMeta])>,
    status: Option<&VaultStatus>,
    copy_clears_in: Option<u64>,
    reveal_secs: u64,
) -> Markup {
    let copy_ok = copy_clears_in.is_some();
    let live = items.iter().filter(|i| !i.deleted).count();
    let deleted = items.len() - live;
    let shown: Vec<&Item> = items.iter().filter(|i| all || !i.deleted).collect();
    let copy_title = if copy_ok {
        "copy to the clipboard"
    } else {
        "copying needs pbcopy, wl-copy, xclip or xsel"
    };
    let body = html! {
        section.card.panel {
            (env_head(env, status, html! {
                a.btn.xs.outline href=(env_url(env, "compare")) { (icon(COMPARE)) "compare" }
                button.btn.xs type="button" data-open="add-secret" { (icon(PLUS)) "add secret" }
            }))
            (tabs(env, "secrets"))
            div.grid.t-secrets {
                div.th { div { "name" } div { "value" } div { "ver" } div { "updated" } div.r { "size" } div {} }
                @for i in &shown {
                    div.trow.gone[i.deleted] {
                        div.mono.b { (i.name) }
                        div.val {
                            @if i.deleted {
                                span.muted { "deleted" }
                            } @else {
                                span.mono.mask data-value { (MASK) }
                                span.muted.small data-countdown {}
                            }
                        }
                        div { "v" (i.version) }
                        div.muted { (ago(i.updated_at)) }
                        div.muted.r { (size(i.size)) }
                        div.acts {
                            @if !i.deleted {
                                button.btn.ixs.ghost type="button" title=(copy_title) disabled[!copy_ok] data-copy=(target(env, &i.name, None)) { (icon(COPY)) }
                                button.btn.ixs.ghost type="button" title={ "reveal for " (reveal_secs) " s" } data-reveal=(target(env, &i.name, None)) { (icon(EYE)) }
                                a.btn.ixs.ghost title="history" href=(history_url(env, &i.name, all)) { (icon(HISTORY)) }
                                button.btn.ixs.ghost.danger type="button" title="delete"
                                    data-api="/api/delete"
                                    data-body=(json!({ "env": env, "name": i.name, "expected": i.version }).to_string())
                                    data-ask=(format!("Delete {}? It becomes a deleted version, and its history is kept.", i.name)) {
                                    (icon(TRASH))
                                }
                            }
                        }
                    }
                }
                @if shown.is_empty() { div.empty { "no secrets yet" } }
            }
            div.cf {
                span {
                    (live) " secrets"
                    @if deleted > 0 {
                        " · "
                        @if all {
                            a href=(env_url(env, "secrets")) { "hide deleted" }
                        } @else {
                            a href={ (env_url(env, "secrets")) "?all=1" } { "show " (deleted) " deleted" }
                        }
                    }
                }
                span.push {
                    @if let Some(secs) = copy_clears_in {
                        "copy goes to the clipboard, never through this page, and clears in " (secs) " s"
                    } @else {
                        "copying needs pbcopy, wl-copy, xclip or xsel; reveal instead"
                    }
                }
            }
        }
        div.scrim.modal data-modal="add-secret" hidden {
            form.dialog data-form="/api/set" {
                input type="hidden" name="env" value=(env);
                div {
                    div.dt { "Add a secret to " (env) }
                    div.dd { "the value travels in this request's body only, and " (f.bin) " ui encrypts it before it reaches the server." }
                }
                label.field { span { "name" } input.input name="name" required autocomplete="off" spellcheck="false"; }
                label.field { span { "value" } textarea.input name="value" required rows="4" autocomplete="off" spellcheck="false" {} }
                div.form-error data-form-error hidden {}
                div.df {
                    button.btn.sm.ghost type="button" data-close { "cancel" span.kbd { "esc" } }
                    button.btn.sm type="submit" { "save" }
                }
            }
        }
        @if let Some((name, versions)) = history {
            (history_sheet(env, name, versions, copy_ok, all))
        }
    };
    layout(f, env, crumb(env), body)
}

fn history_sheet(
    env: &str,
    name: &str,
    versions: &[VersionMeta],
    copy_ok: bool,
    all: bool,
) -> Markup {
    let latest = versions.last().map(|v| v.version);
    let expected = versions.last().filter(|v| !v.tombstone).map(|v| v.version);
    let close = if all {
        format!("{}?all=1", env_url(env, "secrets"))
    } else {
        env_url(env, "secrets")
    };
    html! {
        a.sheet-scrim href=(close) aria-label="close" {}
        aside.sheet {
            div.sheet-head {
                div.mono.sheet-title { (name) }
                div.muted.small { (env) " · every version kept, up to 20" }
                a.btn.ism.ghost.sheet-close href=(close) aria-label="close" { (icon(CLOSE)) }
            }
            div.versions {
                @if versions.is_empty() { div.muted { "no secret named " (name) } }
                @for v in versions.iter().rev() {
                    div.ver.cur[Some(v.version) == latest] {
                        div.row {
                            span.b { "v" (v.version) }
                            @if Some(v.version) == latest && !v.tombstone { span.badge.secondary { "current" } }
                            @if v.tombstone { span.badge.destructive { "deleted" } }
                            span.muted.push {
                                (ago(v.written_at)) " · " (writer_text(&v.written_by))
                                @if !v.tombstone { " · " (size(v.size)) }
                            }
                        }
                        @if v.tombstone {
                            div.muted { "a tombstone: the name was deleted here, and there is no value to copy." }
                        } @else {
                            div.row {
                                span.mono.mask data-value { (MASK) }
                                span.muted.small data-countdown {}
                                span.push.btns {
                                    button.btn.xs.outline type="button" disabled[!copy_ok] data-copy=(target(env, name, Some(v.version))) { (icon(COPY)) "copy" }
                                    button.btn.xs.ghost type="button" data-reveal=(target(env, name, Some(v.version))) { (icon(EYE)) "reveal" }
                                    @if Some(v.version) != latest {
                                        button.btn.xs.ghost type="button"
                                            data-api="/api/restore"
                                            data-body=(json!({ "env": env, "name": name, "version": v.version, "expected": expected }).to_string()) {
                                            (icon(RESTORE)) "restore as v" (latest.map_or(1, |l| l + 1))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            div.sheet-foot.muted.small { "restoring writes a new version with that value. history is never rewritten, and every read here lands in the audit chain." }
        }
    }
}

pub fn tokens(f: &Frame, env: &str, rows: &[TokenRow], status: Option<&VaultStatus>) -> Markup {
    let body = html! {
        section.card.panel {
            (env_head(env, status, html! {
                form.inline data-confirm-form="/api/mint" {
                    input type="hidden" name="env" value=(env);
                    select.input.sm name="scope" {
                        option value="read" { "read" }
                        option value="append" { "append" }
                        option value="meta" { "meta" }
                        option value="admin" { "admin" }
                    }
                    select.input.sm name="ttl" {
                        option value="1d" { "1 day" }
                        option value="7d" { "7 days" }
                        option value="30d" selected { "30 days" }
                        option value="90d" { "90 days" }
                    }
                    button.btn.xs type="submit" { (icon(PLUS)) "mint token" }
                }
            }))
            (tabs(env, "tokens"))
            div.grid.t-tokens {
                div.th { div { "token" } div { "scope" } div { "decrypts" } div { "limited to" } div { "minted" } div { "expires" } div {} }
                @for t in rows {
                    @let id = t.id.to_string();
                    div.trow {
                        div.mono.b title=(id) { (&id[..8.min(id.len())]) }
                        div { span.badge.secondary { (t.scope.to_string()) } }
                        div.muted[!t.scope.get().is_some_and(Scope::bundle_holds_vault_key)] { (decrypts_any(&t.scope)) }
                        div.muted {
                            @match &t.only { Some(l) => { (l.join(", ")) } None => { "—" } }
                        }
                        div.muted { (ago(t.created_at)) }
                        div.muted { (until(t.expires_at)) }
                        div.acts {
                            button.btn.xs.ghost.danger type="button"
                                data-confirm-api="/api/revoke"
                                data-body=(json!({ "env": env, "id": id }).to_string())
                                data-title=(format!("Revoke token {} in {env}", &id[..8.min(id.len())])) {
                                "revoke"
                            }
                        }
                    }
                }
                @if rows.is_empty() { div.empty { "no tokens" } }
            }
            div.cf {
                span { "the server keeps no token labels, so tokens show by id · every scope but meta holds a key (one that decrypts, or a writer key), so revoking any token but meta also rotates the vault" }
                span.push {
                    button.btn.xs.outline type="button"
                        data-confirm-api="/api/rotate"
                        data-body=(json!({ "env": env }).to_string())
                        data-title=(format!("Rotate {env}")) {
                        "rotate now"
                    }
                }
            }
        }
    };
    layout(f, env, crumb(env), body)
}

pub fn audit(
    f: &Frame,
    env: &str,
    report: Result<&AuditReport, String>,
    known: Option<ChainHead>,
    status: Option<&VaultStatus>,
) -> Markup {
    let body = html! {
        section.card.panel {
            (env_head(env, status, html! {}))
            (tabs(env, "audit"))
            @match report {
                Ok(r) => {
                    div.pad {
                        div.alert.ok {
                            (icon(SHIELD))
                            div.at { "chain verified · head at seq " (r.head.map_or(0, |h| h.seq)) }
                            div.ad {
                                @if let Some(k) = known {
                                    "it extends the head this machine stored last time (seq " (k.seq) "), and every entry links to the one before. "
                                } @else {
                                    "this machine had no stored head for this vault: the rows served link to one another, and their head is now stored. "
                                }
                                "names are decrypted here; the server holds only their hashes."
                            }
                        }
                        @if let Some(u) = r.unverifiable {
                            div.alert.warn {
                                (icon(ALERT))
                                div.at { "newer audit rows not verified" }
                                div.ad {
                                    "from seq " (u.from_seq.map_or_else(|| "?".to_owned(), |s| s.to_string()))
                                    " on, the rows are in audit row format " (u.format)
                                    ", newer than this gv reads: they are neither verified nor tampered, and the stored head stops before them. upgrade gv to verify them."
                                }
                            }
                        }
                    }
                    div.grid.t-audit {
                        div.th { div.r { "#" } div { "time" } div { "action" } div { "by" } div { "subject" } }
                        @for l in r.entries.iter().rev().take(300) {
                            div.trow.warn[l.refused] {
                                div.muted.r { (l.seq) }
                                div.muted { (fmt_time(l.ts)) }
                                div.mono.small.amber[l.refused] { (l.action) @if l.refused { " · refused" } }
                                div { (actor_text(&l.actor)) }
                                div.mono { (l.name.as_deref().unwrap_or("")) }
                            }
                        }
                    }
                    div.cf {
                        span { (r.entries.len().min(300)) " rows shown · " (r.new_rows) " new since the stored head" }
                        span.push { "reads made through " (f.bin) " ui are recorded like any other read" }
                    }
                }
                Err(e) => {
                    div.pad {
                        div.alert.fail {
                            (icon(ALERT))
                            div.at { "audit verification failed" }
                            div.ad { (e) " · the stored head was not moved." }
                        }
                    }
                }
            }
        }
    };
    layout(f, env, crumb(env), body)
}

pub fn compare(
    f: &Frame,
    env: &str,
    others: &[String],
    result: Option<(&str, &[CmpRow])>,
) -> Markup {
    let count = |c: Cmp| result.map_or(0, |(_, rows)| rows.iter().filter(|r| r.cmp == c).count());
    let body = html! {
        section.card.panel {
            div.ch {
                div.ct { "compare " span.mono { (env) } }
                div.cd { "decrypted and compared in " (f.bin) " ui, from two independent reads: the server never learns the two are related, and this page gets only same or different." }
                div.ca {
                    form.inline method="get" action=(env_url(env, "compare")) {
                        select.input.sm name="with" {
                            option value="" { "compare with…" }
                            @for o in others {
                                option value=(o) selected[result.is_some_and(|(w, _)| w == o)] { (o) }
                            }
                        }
                        button.btn.xs type="submit" { "compare" }
                    }
                }
            }
            (tabs(env, "compare"))
            @if let Some((with, rows)) = result {
                div.chips {
                    span.chip.on { "all " span.muted { (rows.len()) } }
                    span.chip { span.dot.amber {} "same value " span.muted { (count(Cmp::Same)) } }
                    span.chip { "only in " (env) " " span.muted { (count(Cmp::OnlyA)) } }
                    span.chip { "only in " (with) " " span.muted { (count(Cmp::OnlyB)) } }
                    span.chip { "values differ " span.muted { (count(Cmp::Differ)) } }
                }
                div.grid.t-compare {
                    div.th { div { "secret" } div { (env) } div { (with) } div { "comparison" } }
                    @for r in rows {
                        div.trow.warn[r.cmp == Cmp::Same] {
                            div.mono.b { (r.name) }
                            div.muted[r.a.is_none()] { @match r.a { Some(v) => { "v" (v) } None => { "—" } } }
                            div.muted[r.b.is_none()] { @match r.b { Some(v) => { "v" (v) } None => { "—" } } }
                            div {
                                @match r.cmp {
                                    Cmp::Same => { span.amber { (icon(ALERT)) "same value in both" } }
                                    Cmp::Differ => { span.muted { "values differ" } }
                                    Cmp::OnlyA => { "only in " (env) }
                                    Cmp::OnlyB => { "only in " (with) }
                                }
                            }
                        }
                    }
                    @if rows.is_empty() { div.empty { "neither environment holds a secret" } }
                }
                div.cf {
                    span { "a value shared between environments is flagged, never blocked" }
                    span.push { "every value read for this lands in both audit chains" }
                }
            } @else {
                div.empty { "pick an environment to compare with" }
            }
        }
    };
    layout(f, env, crumb(env), body)
}

pub fn projects(f: &Frame, warnings: &[String]) -> Markup {
    let body = html! {
        section.card.panel {
            div.ch {
                div.ct { "projects on this machine" }
                div.cd { "a project key or an environment kit sits in the keychain; every environment below a held key is derived on use, never stored" }
                div.ca {
                    span.muted.small {
                        "new projects: " span.mono { (f.bin) " init" } " · recovery: " span.mono { (f.bin) " recover" } " · kits and rekey stay in the CLI"
                    }
                }
            }
            @for w in warnings {
                div.pad { div.alert.amber { (icon(ALERT)) div.at { "rediscovery failed" } div.ad { (w) } } }
            }
            div.grid.t-projects {
                div.th { div { "path" } div { "key" } div { "vault" } div {} }
                @for p in &f.rail {
                    div.trow.proj-row {
                        div.path { (icon(if p.key == "environment kit" { KEY } else { FOLDER })) span.b { (p.name) } }
                        div { (p.key) }
                        div.muted.mono { @if let Some(r) = &p.root { (r.vault) } }
                        div.acts { @if let Some(r) = &p.root { a.btn.xs.ghost href=(env_url(&r.path, "secrets")) { "open" } } }
                    }
                    @for e in &p.envs {
                        div.trow {
                            div.path.(depth_class(e.depth)) { span.mono { (e.path) } }
                            div.muted {
                                @if e.kit { "environment kit · keychain" } @else if e.rekeyed { "rekeyed · sealed in its parent" } @else { "derived" }
                            }
                            div.muted.mono { (e.vault) }
                            div.acts {
                                a.btn.xs.ghost href=(env_url(&e.path, "secrets")) { "open" }
                                button.btn.xs.ghost.danger type="button"
                                    data-confirm-api="/api/env/delete"
                                    data-body=(json!({ "path": e.path }).to_string())
                                    data-title=(format!("Delete {}", e.path)) {
                                    "delete"
                                }
                            }
                        }
                    }
                }
                @if f.rail.is_empty() { div.empty { "no projects here yet: create one with " (f.bin) " init, or bring one with " (f.bin) " recover" } }
            }
            div.cf {
                form.inline data-form="/api/env/add" {
                    input.input.sm name="path" placeholder="project/environment" required autocomplete="off" spellcheck="false";
                    button.btn.xs type="submit" { (icon(PLUS)) "add environment" }
                    span.muted.small { "creating runs a short proof-of-work" }
                }
            }
        }
    };
    layout(f, "projects", html! { span.b { "projects" } }, body)
}

pub fn problem(f: &Frame, message: &str) -> Markup {
    let body = html! {
        section.card.panel {
            div.pad.first {
                div.alert.fail { (icon(ALERT)) div.at { (f.bin) " ui could not do that" } div.ad { (message) } }
            }
        }
    };
    layout(f, "problem", html! { span.muted { "problem" } }, body)
}

pub fn not_found(f: &Frame) -> Markup {
    problem(f, "there is no such page")
}
