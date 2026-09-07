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
        Some("parse") => match args.get(2) {
            Some(dir) => parse_report(dir, args.get(3).map(String::as_str)),
            None => usage(),
        },
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: parapet-conformance compile <patterns.json>");
    eprintln!("       parapet-conformance parse <crs-rules-dir> [crs-4.9.0]");
    ExitCode::FAILURE
}

/// Parse every `.conf` in a CRS rules directory. Any failure is a defect: CRS
/// is the compatibility bar, so a rule Parapet cannot parse is a rule it would
/// have silently failed to enforce.
/// Directive counts for a known CRS release, measured independently of the
/// parser. Asserting them catches a parser that stops recognising a construct
/// and silently returns fewer rules, which a zero-error run alone would miss.
struct Expected {
    rules: usize,
    secactions: usize,
    markers: usize,
    signatures: usize,
    chained: usize,
    with_id: usize,
}

fn expected_for(tag: &str) -> Option<Expected> {
    match tag {
        "crs-4.9.0" => Some(Expected {
            rules: 660,
            secactions: 7,
            markers: 29,
            signatures: 1,
            chained: 73,
            with_id: 587,
        }),
        _ => None,
    }
}

fn parse_report(dir: &str, expect_tag: Option<&str>) -> ExitCode {
    let mut files: Vec<_> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "conf"))
            .collect(),
        Err(e) => {
            eprintln!("cannot read {dir}: {e}");
            return ExitCode::FAILURE;
        }
    };
    files.sort();

    let mut rules = 0usize;
    let mut secactions = 0usize;
    let mut markers = 0usize;
    let mut signatures = 0usize;
    let mut chained = 0usize;
    let mut with_id = 0usize;
    let mut errors = Vec::new();

    for path in &files {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();
        let src = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                errors.push(format!("{name}: cannot read: {e}"));
                continue;
            }
        };
        let (directives, file_errors) = parapet::parse_all(&src, &name);
        for e in file_errors {
            errors.push(e.to_string());
        }
        {
            {
                for d in &directives {
                    match d {
                        parapet::Directive::Rule(r) => {
                            rules += 1;
                            if r.is_chained() {
                                chained += 1;
                            }
                            if r.id().is_some() {
                                with_id += 1;
                            }
                        }
                        parapet::Directive::Action(_) => secactions += 1,
                        parapet::Directive::Marker(_) => markers += 1,
                        parapet::Directive::ComponentSignature(_) => signatures += 1,
                    }
                }
            }
        }
    }

    println!("files parsed          : {}", files.len());
    println!("SecRule               : {rules}");
    println!("  chain starters      : {chained}");
    println!("  carrying an id      : {with_id}");
    println!("SecAction             : {secactions}");
    println!("SecMarker             : {markers}");
    println!("SecComponentSignature : {signatures}");
    println!("parse errors          : {}", errors.len());
    let mut mismatches: Vec<String> = Vec::new();
    if let Some(tag) = expect_tag {
        let Some(exp) = expected_for(tag) else {
            eprintln!("unknown expectation set {tag:?}");
            return ExitCode::FAILURE;
        };
        let mut check = |what: &str, got: usize, want: usize| {
            if got != want {
                mismatches.push(format!("{what}: expected {want}, parsed {got}"));
            }
        };
        check("SecRule", rules, exp.rules);
        check("SecAction", secactions, exp.secactions);
        check("SecMarker", markers, exp.markers);
        check("SecComponentSignature", signatures, exp.signatures);
        check("chain starters", chained, exp.chained);
        check("rules carrying an id", with_id, exp.with_id);
        println!(
            "\nexpectation set {tag}: {}",
            if mismatches.is_empty() {
                "matched"
            } else {
                "MISMATCH"
            }
        );
        for m in &mismatches {
            println!("  {m}");
        }
    }
    for e in errors.iter().take(25) {
        println!("  {e}");
    }
    if errors.len() > 25 {
        println!("  ... and {} more", errors.len() - 25);
    }

    if errors.is_empty() && mismatches.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
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
