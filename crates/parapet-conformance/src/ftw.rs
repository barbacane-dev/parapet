//! The CRS regression suite, run in process.
//!
//! `go-ftw` normally drives a live web server with a WAF in front and greps
//! the error log. Running the same corpus directly against the library is
//! faster, deterministic, and gives a line number when something fails, at the
//! cost of not exercising a real HTTP stack. The assertions are the same ones:
//! which rule ids fired.
//!
//! Stages run in detection-only mode. The assertions are about which rules
//! appear in the log, so a disruptive action that ended the transaction early
//! would hide later rules and turn a correct engine into a failing one.

use std::collections::{BTreeMap, BTreeSet};

use parapet::matcher::DirDataLoader;
use parapet::transaction::EngineMode;
use parapet::{RuleSet, Transaction};

#[derive(serde::Deserialize)]
struct Stage {
    file: String,
    #[allow(dead_code)]
    rule_id: Option<u32>,
    test_id: Option<u32>,
    stage: u32,
    desc: String,
    method: String,
    uri: String,
    version: String,
    headers: BTreeMap<String, String>,
    data: Option<String>,
    expect_ids: Vec<u32>,
    no_expect_ids: Vec<u32>,
    #[serde(default)]
    status: Option<serde_json::Value>,
}

impl Stage {
    fn label(&self) -> String {
        format!(
            "{}#{}.{}",
            self.file.trim_end_matches(".yaml"),
            self.test_id.unwrap_or(0),
            self.stage
        )
    }
}

/// The configuration CRS documents for running its own regression suite
/// (`tests/regression/README.md`). Injected verbatim rather than hand-seeding
/// variables, so the harness cannot drift from what the corpus assumes.
///
/// The paranoia level is the load-bearing part: most of the corpus exercises
/// rules tagged `paranoia-level/2` and above, which the default level skips
/// entirely.
const CRS_TEST_CONFIG: &str = r#"
SecAction "id:900005,  phase:1,  nolog,  pass,  ctl:ruleEngine=DetectionOnly,  ctl:ruleRemoveById=910000,  setvar:tx.blocking_paranoia_level=4,  setvar:tx.crs_validate_utf8_encoding=1,  setvar:tx.arg_name_length=100,  setvar:tx.arg_length=400,  setvar:tx.max_file_size=64100,  setvar:tx.combined_file_sizes=65535"
"#;

/// Load the rule set once: setup file, the documented test config, then every
/// rule file in order.
fn load_ruleset(rules_dir: &str) -> Result<(RuleSet, usize), String> {
    let mut directives = Vec::new();

    let setup = std::path::Path::new(rules_dir)
        .parent()
        .map(|p| p.join("crs-setup.conf.example"));
    if let Some(setup) = setup.filter(|p| p.exists()) {
        let src = std::fs::read_to_string(&setup).map_err(|e| format!("crs-setup: {e}"))?;
        let (parsed, errors) = parapet::parse_all(&src, "crs-setup.conf");
        if !errors.is_empty() {
            return Err(format!("crs-setup.conf: {}", errors[0]));
        }
        directives.extend(parsed);
    }

    let (config, errors) = parapet::parse_all(CRS_TEST_CONFIG, "crs-test-config");
    if !errors.is_empty() {
        return Err(format!("test config: {}", errors[0]));
    }
    directives.extend(config);

    let mut sources: Vec<_> = std::fs::read_dir(rules_dir)
        .map_err(|e| format!("cannot read {rules_dir}: {e}"))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "conf"))
        .collect();
    sources.sort();

    for path in &sources {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();
        let src = std::fs::read_to_string(path).map_err(|e| format!("{name}: {e}"))?;
        let (parsed, errors) = parapet::parse_all(&src, &name);
        if !errors.is_empty() {
            return Err(format!("{name}: {}", errors[0]));
        }
        directives.extend(parsed);
    }

    let loader = DirDataLoader::new(rules_dir);
    let (ruleset, compile_errors) = RuleSet::compile_all(&directives, &loader);
    Ok((ruleset, compile_errors.len()))
}

/// Run the regression corpus.
///
/// `min_pass_rate` makes this a ratchet rather than a pass/fail gate: the
/// suite is not at 100% yet, and a threshold that only ever goes up catches a
/// regression without pretending the remaining failures do not exist.
/// Returns the number of failing stages.
pub fn run(
    rules_dir: &str,
    corpus_path: &str,
    min_pass_rate: Option<f64>,
) -> Result<usize, String> {
    let (ruleset, refused) = load_ruleset(rules_dir)?;
    let raw = std::fs::read_to_string(corpus_path)
        .map_err(|e| format!("cannot read {corpus_path}: {e}"))?;
    let stages: Vec<Stage> =
        serde_json::from_str(&raw).map_err(|e| format!("cannot parse {corpus_path}: {e}"))?;

    println!("rules compiled : {}", ruleset.rule_count());
    println!("rules refused  : {refused}");
    println!("stages         : {}", stages.len());
    println!();

    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;
    // Which expected rule ids never fired, and how often. This is the number
    // that says where the remaining work is.
    let mut never_fired: BTreeMap<u32, usize> = BTreeMap::new();
    let mut false_positives: BTreeMap<u32, usize> = BTreeMap::new();
    let mut failing_files: BTreeMap<String, usize> = BTreeMap::new();
    let mut examples: Vec<String> = Vec::new();

    for stage in &stages {
        // `status` assertions need a blocking run and a real HTTP response;
        // they are counted separately rather than guessed at.
        if stage.status.is_some() && stage.expect_ids.is_empty() && stage.no_expect_ids.is_empty() {
            skipped += 1;
            continue;
        }

        let fired = run_stage(&ruleset, stage);

        let missing: Vec<u32> = stage
            .expect_ids
            .iter()
            .copied()
            .filter(|id| !fired.contains(id))
            .collect();
        let unexpected: Vec<u32> = stage
            .no_expect_ids
            .iter()
            .copied()
            .filter(|id| fired.contains(id))
            .collect();

        if missing.is_empty() && unexpected.is_empty() {
            passed += 1;
            continue;
        }

        failed += 1;
        *failing_files.entry(stage.file.clone()).or_default() += 1;
        for id in &missing {
            *never_fired.entry(*id).or_default() += 1;
        }
        for id in &unexpected {
            *false_positives.entry(*id).or_default() += 1;
        }
        // PARAPET_FOCUS=<rule id> dumps every failing stage involving that
        // rule in full, which is how you actually debug one.
        if let Ok(focus) = std::env::var("PARAPET_FOCUS") {
            if let Ok(focus) = focus.parse::<u32>() {
                if missing.contains(&focus) || unexpected.contains(&focus) {
                    println!(
                        "--- {} {}\n    {} {} ({})\n    data: {:?}\n    expected {:?}  missing {:?}  unexpected {:?}\n    fired: {:?}",
                        stage.label(),
                        stage.desc,
                        stage.method,
                        stage.uri,
                        stage.version,
                        stage.data.as_deref().unwrap_or(""),
                        stage.expect_ids,
                        missing,
                        unexpected,
                        fired.iter().copied().collect::<Vec<_>>(),
                    );
                }
            }
        }
        if examples.len() < 12 {
            examples.push(format!(
                "{:<28} {}\n      expected {:?} missing {:?} unexpected {:?}",
                stage.label(),
                stage.desc,
                stage.expect_ids,
                missing,
                unexpected
            ));
        }
    }

    let total = passed + failed;
    let rate = if total > 0 {
        100.0 * passed as f64 / total as f64
    } else {
        0.0
    };
    println!("passed         : {passed}");
    println!("failed         : {failed}");
    println!("skipped        : {skipped} (status-only assertions)");
    println!("pass rate      : {rate:.1}%");

    println!("\nexpected rules that never fired (top 20):");
    let mut ranked: Vec<_> = never_fired.iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (id, count) in ranked.iter().take(20) {
        println!("  rule {id}: {count} stages");
    }

    if !false_positives.is_empty() {
        println!("\nrules that fired when they should not (top 20):");
        let mut ranked: Vec<_> = false_positives.iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        for (id, count) in ranked.iter().take(20) {
            println!("  rule {id}: {count} stages");
        }
    }

    println!("\nworst files (top 15):");
    let mut ranked: Vec<_> = failing_files.iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (file, count) in ranked.iter().take(15) {
        println!("  {file}: {count} failing stages");
    }

    println!("\nexamples:");
    for e in &examples {
        println!("  {e}");
    }

    if let Some(floor) = min_pass_rate {
        println!("\nbaseline       : {floor:.1}%");
        if rate + 1e-9 < floor {
            return Err(format!(
                "pass rate {rate:.1}% fell below the {floor:.1}% baseline"
            ));
        }
        println!("at or above the baseline");
        return Ok(0);
    }

    Ok(failed)
}

fn run_stage(ruleset: &RuleSet, stage: &Stage) -> BTreeSet<u32> {
    let mut tx = Transaction::new(ruleset, EngineMode::DetectionOnly);
    tx.set_remote_addr("127.0.0.1");
    tx.process_uri(&stage.method, &stage.uri, &stage.version);

    let has_content_type = stage
        .headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case("content-type"));
    let has_content_length = stage
        .headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case("content-length"));

    for (name, value) in &stage.headers {
        tx.add_request_header(name, value);
    }

    // FTW completes the request the way a client would: a body implies a
    // Content-Type and Content-Length unless the test set them. Without this
    // the urlencoded parser never runs and ARGS_POST stays empty, which fails
    // most body-carrying stages for a reason that has nothing to do with rules.
    let content_type = if has_content_type {
        stage
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone())
    } else if stage.data.is_some() {
        let implied = "application/x-www-form-urlencoded".to_string();
        tx.add_request_header("Content-Type", &implied);
        Some(implied)
    } else {
        None
    };

    if let Some(body) = &stage.data {
        if !has_content_length {
            tx.add_request_header("Content-Length", &body.len().to_string());
        }
    }

    tx.process_request_headers();
    if let Some(body) = &stage.data {
        tx.set_request_body(body.as_bytes(), content_type.as_deref());
    }
    tx.process_request_body();

    // Response phases run so phase 3-5 rules get a chance to fire; the corpus
    // has no real upstream response, so this is an empty 200.
    tx.set_response_status(200);
    tx.process_response_headers();
    tx.set_response_body(b"");
    tx.process_response_body();
    tx.process_logging();

    tx.matched_ids().into_iter().collect()
}
