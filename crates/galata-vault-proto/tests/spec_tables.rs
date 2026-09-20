//! The specification's tables against the code (`docs/spec/README.md#7`):
//! the error table (`docs/spec/http-api.md#5.2`) is exactly `ErrorCode`, with
//! each code's status and retry class, and every section a vector cites
//! exists.
//!
//! Reads `docs/spec/` and `testdata/vectors/` from the workspace, so it is
//! left out of the published package (`exclude` in Cargo.toml).

use std::collections::BTreeMap;
use std::path::PathBuf;

use galata_vault_proto::api::{ErrorCode, Retry};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn spec(file: &str) -> String {
    let path = root().join("docs/spec").join(file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

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

fn retry_word(retry: Retry) -> &'static str {
    match retry {
        Retry::Yes => "yes",
        Retry::Refresh => "refresh",
        Retry::No => "no",
        _ => "a retry class the table cannot name",
    }
}

#[test]
fn the_error_table_is_exactly_error_code() {
    let rows = table(&spec("http-api.md"), "5.2");
    assert_eq!(
        rows[0][..3],
        ["Code", "Status", "Retry"],
        "the table's columns"
    );
    let mut documented = BTreeMap::new();
    for row in &rows[1..] {
        let code = row[0].trim_matches('`').to_owned();
        let previous = documented.insert(code.clone(), (row[1].clone(), row[2].clone()));
        assert!(previous.is_none(), "http-api.md#5.2 lists {code} twice");
    }
    let mut problems = Vec::new();
    for code in ErrorCode::ALL {
        let wire = serde_json::to_value(code).unwrap();
        if wire != code.as_str() {
            problems.push(format!("{} goes on the wire as {wire}", code.as_str()));
        }
        match documented.remove(code.as_str()) {
            None => problems.push(format!(
                "{} is an ErrorCode but http-api.md#5.2 does not list it",
                code.as_str()
            )),
            Some((status, retry)) => {
                if status != code.status().to_string() {
                    problems.push(format!(
                        "{}: http-api.md#5.2 says status {status}, the code says {}",
                        code.as_str(),
                        code.status()
                    ));
                }
                if retry != retry_word(code.retry()) {
                    problems.push(format!(
                        "{}: http-api.md#5.2 says retry {retry}, the code says {}",
                        code.as_str(),
                        retry_word(code.retry())
                    ));
                }
            }
        }
    }
    for code in documented.keys() {
        problems.push(format!(
            "{code} is in http-api.md#5.2 but is not an ErrorCode"
        ));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn every_section_a_vector_cites_exists() {
    let dir = root().join("testdata/vectors/v1");
    let mut docs: BTreeMap<String, String> = BTreeMap::new();
    let mut problems = Vec::new();
    let mut checked = 0;
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    assert!(files.len() >= 13, "vector files in {}", dir.display());
    for path in files {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let mut anchors = vec![doc["spec"].as_str().unwrap_or("").to_owned()];
        for case in doc["cases"].as_array().into_iter().flatten() {
            anchors.push(case["spec"].as_str().unwrap_or("").to_owned());
        }
        for anchor in anchors {
            checked += 1;
            let Some((file, id)) = anchor.split_once('#') else {
                problems.push(format!("{name}: {anchor:?} is not file#section"));
                continue;
            };
            let text = docs.entry(file.to_owned()).or_insert_with(|| {
                std::fs::read_to_string(root().join("docs/spec").join(file)).unwrap_or_default()
            });
            if !text.contains(&format!("<a id=\"{id}\"></a>")) {
                problems.push(format!("{name}: {anchor} does not exist"));
            }
        }
    }
    problems.sort();
    problems.dedup();
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    assert!(checked > 300, "only {checked} anchors checked");
}
