//! Measures Parapet against the OWASP Core Rule Set.
//!
//! Three checks, in increasing strength:
//!
//! 1. **Compile coverage.** Every `@rx` operand in a CRS release compiles.
//! 2. **Differential.** Where Parapet rewrites a pattern to compile it, the
//!    rewrite agrees with Go/RE2 (the engine Coraza uses) on a large input
//!    corpus. A rewrite that changes match behaviour is a defect.
//! 3. **Regression.** The CRS regression corpus passes via `go-ftw`.
//!
//! Check 3 gates releases. Checks 1 and 2 run in CI on every commit.
//!
//! Usage:
//!   parapet-conformance extract <crs-rules-dir> <out.json>
//!   parapet-conformance compile <patterns.json>

use std::collections::BTreeMap;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("compile") => match args.get(2) {
            Some(path) => compile_report(path),
            None => usage(),
        },
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: parapet-conformance compile <patterns.json>");
    ExitCode::FAILURE
}

/// Report how much of a CRS `@rx` corpus compiles, and what needed repair.
fn compile_report(path: &str) -> ExitCode {
    let raw = match std::fs::read_to_string(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let items: Vec<serde_json::Value> = match serde_json::from_str(&raw) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("cannot parse {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Every pattern counts. Chained rules carry `id:` only on the chain
    // starter, so keying on a present id would silently drop the rest, and a
    // conformance tool that skips input it cannot label is worthless.
    let mut uniq: BTreeMap<&str, String> = BTreeMap::new();
    let mut unlabelled = 0usize;
    for it in &items {
        let Some(pattern) = it["pattern"].as_str() else {
            eprintln!("entry without a pattern field: {it}");
            return ExitCode::FAILURE;
        };
        let label = match it["id"].as_str() {
            Some(id) => id.to_string(),
            None => {
                unlabelled += 1;
                format!("(chained, {})", it["file"].as_str().unwrap_or("?"))
            }
        };
        uniq.entry(pattern).or_insert(label);
    }

    let mut as_authored = 0usize;
    let mut repaired = Vec::new();
    let mut failed = Vec::new();

    for (pattern, label) in &uniq {
        match parapet::regex_compat::compile(pattern) {
            Ok(c) if c.repaired_from.is_none() => as_authored += 1,
            Ok(_) => repaired.push(label.clone()),
            Err(e) => failed.push((label.clone(), e.source_error)),
        }
    }

    println!("unique @rx patterns : {}", uniq.len());
    println!("  of which unlabelled (chained rules): {unlabelled}");
    println!("compile as authored : {as_authored}");
    println!("compile after repair: {}  {:?}", repaired.len(), repaired);
    println!("cannot compile      : {}", failed.len());
    for (label, err) in &failed {
        println!("  rule {label}: {err}");
    }

    if failed.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
