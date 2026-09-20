//! The endpoint table in `docs/spec/http-api.md#2` is exactly the server's
//! route table, [`galata_vault_server_core::ROUTES`], by method, path and
//! authentication scheme (`docs/spec/README.md#7`).
//!
//! Reads `docs/spec/` from the workspace, so it is left out of the published
//! package (`exclude` in Cargo.toml).

use std::collections::BTreeSet;
use std::path::PathBuf;

use galata_vault_server_core::ROUTES;

/// The first Markdown table in section `anchor` of `doc`: its header, then
/// its rows, each as trimmed cells.
fn table(doc: &str, anchor: &str) -> Vec<Vec<String>> {
    let marker = format!("<a id=\"{anchor}\"></a>");
    let start = doc
        .find(&marker)
        .unwrap_or_else(|| panic!("no section {anchor}"));
    let rest = &doc[start + marker.len()..];
    let section = &rest[..rest.find("<a id=").unwrap_or(rest.len())];
    let mut rows: Vec<Vec<String>> = Vec::new();
    for line in section.lines().map(str::trim) {
        if !line.starts_with('|') {
            if rows.is_empty() {
                continue;
            }
            break;
        }
        let cells: Vec<String> = line
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().to_owned())
            .collect();
        if cells
            .iter()
            .all(|c| c.chars().all(|ch| ch == '-' || ch == ':'))
        {
            continue;
        }
        rows.push(cells);
    }
    assert!(!rows.is_empty(), "section {anchor} has no table");
    rows
}

#[test]
fn the_endpoint_table_is_exactly_the_route_table() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/spec/http-api.md");
    let doc = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let rows = table(&doc, "2");
    assert_eq!(
        rows[0][..3],
        ["Method", "Path", "Auth"],
        "the table's columns"
    );
    let mut documented = BTreeSet::new();
    for row in &rows[1..] {
        let key = (
            row[0].clone(),
            row[1].trim_matches('`').to_owned(),
            row[2].clone(),
        );
        assert!(
            documented.insert(key.clone()),
            "http-api.md#2 lists {key:?} twice"
        );
    }
    let mut problems = Vec::new();
    for route in ROUTES {
        let key = (
            route.method.to_owned(),
            route.path.to_owned(),
            route.auth.as_str().to_owned(),
        );
        if !documented.remove(&key) {
            problems.push(format!(
                "{} {} (auth: {}) is served, but http-api.md#2 does not list it so",
                route.method,
                route.path,
                route.auth.as_str()
            ));
        }
    }
    for (method, path, auth) in documented {
        problems.push(format!(
            "{method} {path} (auth: {auth}) is in http-api.md#2, but no route serves it so"
        ));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
