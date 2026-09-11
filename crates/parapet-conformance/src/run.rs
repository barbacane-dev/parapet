//! End-to-end run: real CRS rules against real requests.
//!
//! The first check that exercises everything at once. Compile coverage says
//! the rules loaded; this says whether they fire on attacks and stay quiet on
//! benign traffic, which is the only property that matters in the end.

use parapet::matcher::DirDataLoader;
use parapet::transaction::EngineMode;
use parapet::{RuleSet, Transaction, Verdict};

struct Case {
    name: &'static str,
    method: &'static str,
    uri: &'static str,
    body: Option<(&'static str, &'static str)>,
    /// Whether CRS at the default paranoia level should block this.
    expect_block: bool,
    /// Set when a miss is a known, attributed gap rather than a defect. The
    /// case still runs and is still reported; it just does not fail the build.
    known_gap: Option<&'static str>,
}

const CASES: &[Case] = &[
    // Benign traffic. A false positive here is as much a defect as a miss.
    Case {
        name: "static page",
        method: "GET",
        uri: "/index.html",
        body: None,
        expect_block: false,
        known_gap: None,
    },
    Case {
        name: "plain query",
        method: "GET",
        uri: "/search?q=hello+world",
        body: None,
        expect_block: false,
        known_gap: None,
    },
    Case {
        name: "numeric id",
        method: "GET",
        uri: "/item?id=12345",
        body: None,
        expect_block: false,
        known_gap: None,
    },
    Case {
        name: "normal post",
        method: "POST",
        uri: "/login",
        body: Some((
            "application/x-www-form-urlencoded",
            "user=alice&pass=hunter2",
        )),
        expect_block: false,
        known_gap: None,
    },
    Case {
        name: "path with dots in name",
        method: "GET",
        uri: "/files/report.2026.pdf",
        body: None,
        expect_block: false,
        known_gap: None,
    },
    // SQL injection.
    Case {
        name: "sqli tautology",
        method: "GET",
        uri: "/item?id=1%27%20OR%20%271%27%3D%271",
        body: None,
        expect_block: true,
        // Caught by rule 942100, the libinjection SQLi rule (@detectSQLi).
        known_gap: None,
    },
    Case {
        name: "sqli union select",
        method: "GET",
        uri: "/item?id=1%20UNION%20SELECT%20password%20FROM%20users",
        body: None,
        expect_block: true,
        known_gap: None,
    },
    Case {
        name: "sqli comment evasion",
        method: "GET",
        uri: "/item?id=1%20UN/**/ION%20SEL/**/ECT%201",
        body: None,
        expect_block: true,
        known_gap: None,
    },
    Case {
        name: "sqli in body",
        method: "POST",
        uri: "/search",
        body: Some(("application/x-www-form-urlencoded", "q=1'+or+sleep(5)%23")),
        expect_block: true,
        known_gap: None,
    },
    // Cross-site scripting.
    Case {
        name: "xss script tag",
        method: "GET",
        uri: "/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        body: None,
        expect_block: true,
        known_gap: None,
    },
    Case {
        name: "xss img onerror",
        method: "GET",
        uri: "/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E",
        body: None,
        expect_block: true,
        known_gap: None,
    },
    Case {
        name: "xss javascript uri",
        method: "GET",
        uri: "/redirect?to=javascript%3Aalert%281%29",
        body: None,
        expect_block: true,
        known_gap: None,
    },
    // Local file inclusion and traversal.
    Case {
        name: "lfi etc passwd",
        method: "GET",
        uri: "/download?file=../../../../etc/passwd",
        body: None,
        expect_block: true,
        known_gap: None,
    },
    Case {
        name: "lfi encoded traversal",
        method: "GET",
        uri: "/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        body: None,
        expect_block: true,
        known_gap: None,
    },
    // Remote command execution.
    Case {
        name: "rce semicolon",
        method: "GET",
        uri: "/ping?host=127.0.0.1%3Bcat%20/etc/passwd",
        body: None,
        expect_block: true,
        known_gap: None,
    },
    Case {
        name: "rce shell expression",
        method: "GET",
        uri: "/ping?host=%24%28id%29",
        body: None,
        expect_block: true,
        known_gap: None,
    },
    // Rule 932131 covers bare backticks and is tagged paranoia-level/2, so CRS
    // at the default PL1 allows this. Asserting that keeps a future change from
    // silently raising the effective paranoia level.
    Case {
        name: "rce backtick (PL2 only)",
        method: "GET",
        uri: "/ping?host=%60id%60",
        body: None,
        expect_block: false,
        known_gap: None,
    },
    // Protocol rules.
    Case {
        name: "null byte",
        method: "GET",
        uri: "/file?name=a%00.php",
        body: None,
        expect_block: true,
        known_gap: None,
    },
];

/// Compile CRS and run the request corpus through it.
pub fn run(rules_dir: &str) -> Result<usize, String> {
    // crs-setup.conf.example sits beside the rules directory and carries the
    // SecDefaultAction settings plus the guard rule 901001 checks for. Without
    // it CRS correctly refuses to run at all.
    let setup = std::path::Path::new(rules_dir)
        .parent()
        .map(|p| p.join("crs-setup.conf.example"));

    let mut sources: Vec<_> = std::fs::read_dir(rules_dir)
        .map_err(|e| format!("cannot read {rules_dir}: {e}"))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "conf"))
        .collect();
    sources.sort();

    let mut directives = Vec::new();
    if let Some(setup) = setup.filter(|p| p.exists()) {
        let src = std::fs::read_to_string(&setup).map_err(|e| format!("crs-setup: {e}"))?;
        let (parsed, errors) = parapet::parse_all(&src, "crs-setup.conf");
        if !errors.is_empty() {
            return Err(format!(
                "crs-setup.conf: {} parse errors, first: {}",
                errors.len(),
                errors[0]
            ));
        }
        println!("crs-setup loaded : {} directives", parsed.len());
        directives.extend(parsed);
    }
    for path in &sources {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();
        let src = std::fs::read_to_string(path).map_err(|e| format!("{name}: {e}"))?;
        let (parsed, errors) = parapet::parse_all(&src, &name);
        if !errors.is_empty() {
            return Err(format!("{name}: {} parse errors", errors.len()));
        }
        directives.extend(parsed);
    }

    let loader = DirDataLoader::new(rules_dir);
    // compile_all, not compile: this tool measures progress and reports any
    // rule that fails to compile rather than aborting on the first one.
    let (ruleset, compile_errors) = RuleSet::compile_all(&directives, &loader);

    println!("rules compiled   : {}", ruleset.rule_count());
    println!("markers          : {}", ruleset.marker_count());
    for phase in [1, 2, 3, 4, 5] {
        let p = match phase {
            1 => parapet::Phase::RequestHeaders,
            2 => parapet::Phase::RequestBody,
            3 => parapet::Phase::ResponseHeaders,
            4 => parapet::Phase::ResponseBody,
            _ => parapet::Phase::Logging,
        };
        println!("  phase {phase}         : {}", ruleset.rules_in_phase(p));
    }
    println!("rules refused    : {}", compile_errors.len());
    println!();

    let mut wrong = 0usize;
    let mut gaps = 0usize;
    println!("{:<26} {:>14} {:>5}  expected", "case", "verdict", "score");
    for case in CASES {
        let mut tx = Transaction::new(&ruleset, EngineMode::Blocking);
        tx.set_remote_addr("203.0.113.7");
        tx.process_uri(case.method, case.uri, "HTTP/1.1");
        tx.add_request_header("Host", "example.test");
        tx.add_request_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)");
        tx.add_request_header("Accept", "text/html,application/xhtml+xml");
        if let Some((ct, _)) = case.body {
            tx.add_request_header("Content-Type", ct);
        }
        let mut verdict = tx.process_request_headers();
        if verdict == Verdict::Allow {
            if let Some((ct, body)) = case.body {
                tx.set_request_body(body.as_bytes(), Some(ct));
            }
            verdict = tx.process_request_body();
        }

        let blocked = verdict != Verdict::Allow;
        let by = match &verdict {
            Verdict::Deny { rule_id, .. } => format!(" by {rule_id}"),
            Verdict::Allow => String::new(),
        };
        let score = tx.anomaly_score("blocking_inbound_anomaly_score");
        let ok = blocked == case.expect_block;
        if !ok {
            match case.known_gap {
                Some(_) => gaps += 1,
                None => wrong += 1,
            }
        }
        println!(
            "{:<26} {:>8}{:<6} {:>5}  {}{}",
            case.name,
            if blocked { "BLOCK" } else { "allow" },
            by,
            score,
            if case.expect_block { "block" } else { "allow" },
            match (ok, case.known_gap) {
                (true, _) => String::new(),
                (false, Some(why)) => format!("   <- known gap: {why}"),
                (false, None) => "   <- WRONG".to_string(),
            },
        );
        if !ok || std::env::var("PARAPET_VERBOSE").is_ok() {
            for m in tx.matches().iter().take(6) {
                println!(
                    "      rule {:?} {} {}",
                    m.id.unwrap_or(0),
                    m.message,
                    m.matched_name
                );
            }
        }
    }

    println!("\ncases            : {}", CASES.len());
    println!("known gaps       : {gaps}");
    println!("wrong verdicts   : {wrong}");
    Ok(wrong)
}
