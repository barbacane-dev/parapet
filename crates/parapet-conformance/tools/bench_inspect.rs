//! Per-request cost of inspection with the real Core Rule Set.
//!
//! Isolates the engine from HTTP overhead: the question is what inspection
//! adds to a request. Run it as a standalone binary against a rules directory
//! that includes `crs-setup.conf.example`, which the assertion below enforces:
//! without the setup file CRS blocks everything at rule 901001 and the
//! measurement is of an early refusal rather than of inspection.
//!
//! ```text
//! cp crs/rules/*.conf crs/rules/*.data bench-rules/
//! cp crs/crs-setup.conf.example bench-rules/000-crs-setup.conf
//! cargo run --release -p parapet-conformance --example bench_inspect -- bench-rules
//! ```
// A standalone measurement tool: it reads a rules directory and panics on any
// malformed input rather than handling it, which is what you want from a
// benchmark harness.
#![allow(clippy::unwrap_used)]

use parapet::transaction::EngineMode;
use parapet::{RuleSet, Transaction, Verdict};
use std::time::Instant;

struct Case {
    name: &'static str,
    method: &'static str,
    uri: &'static str,
    body: Option<(&'static str, &'static str)>,
    /// A `Cookie` header value. CRS resolves REQUEST_COOKIES with a
    /// `!REQUEST_COOKIES:/__utm/` exclusion on 162 rules, so cookie count is a
    /// first-order cost and a realistic browser request carries several.
    cookies: Option<&'static str>,
}

fn main() {
    let dir = std::env::args().nth(1).expect("crs rules dir");
    let mut directives = Vec::new();
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "conf"))
        .collect();
    paths.sort();
    for p in &paths {
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let src = std::fs::read_to_string(p).unwrap();
        let (parsed, errors) = parapet::parse_all(&src, &name);
        assert!(errors.is_empty(), "{name}: {:?}", errors.first());
        directives.extend(parsed);
    }

    let loader = parapet::DirDataLoader::new(&dir);
    let start = Instant::now();
    let (rules, errors) = RuleSet::compile_all(&directives, &loader);
    println!(
        "rules={} refused={} build={:.0}ms",
        rules.rule_count(),
        errors.len(),
        start.elapsed().as_secs_f64() * 1000.0
    );

    // A typical browser cookie jar: session cookies plus the analytics cookies
    // CRS explicitly excludes (__utm*, _pk_ref).
    const BROWSER_COOKIES: &str = "sessionid=abc123def456; csrftoken=xyz789; __utma=1.2.3.4.5; __utmb=6.7.8.9; __utmc=10; __utmz=11.12.13.14.utmcsr=google; _pk_ref=%5B%22%22%2C%22%22%5D; theme=dark; lang=en";
    // A heavier jar, to show how cost scales with cookie count.
    let many = (0..24)
        .map(|i| format!("c{i}=v{i}"))
        .collect::<Vec<_>>()
        .join("; ");
    let many_cookies: &'static str = Box::leak(many.into_boxed_str());

    let cases = [
        Case {
            name: "benign GET, no query",
            method: "GET",
            uri: "/index.html",
            body: None,
            cookies: None,
        },
        Case {
            name: "benign GET, short query",
            method: "GET",
            uri: "/search?q=hello+world",
            body: None,
            cookies: None,
        },
        Case {
            name: "benign GET, 10 params",
            method: "GET",
            uri: "/s?a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8&i=9&j=10",
            body: None,
            cookies: None,
        },
        Case {
            name: "benign POST, form body",
            method: "POST",
            uri: "/login",
            body: Some((
                "application/x-www-form-urlencoded",
                "user=alice&pass=hunter2",
            )),
            cookies: None,
        },
        Case {
            name: "benign POST, 4KB JSON",
            method: "POST",
            uri: "/api",
            body: Some(("application/json", "")),
            cookies: None,
        },
        Case {
            name: "benign GET, browser cookies",
            method: "GET",
            uri: "/index.html",
            body: None,
            cookies: Some(BROWSER_COOKIES),
        },
        Case {
            name: "benign GET, 24 cookies",
            method: "GET",
            uri: "/index.html",
            body: None,
            cookies: Some(many_cookies),
        },
        Case {
            name: "attack, sqli (blocks)",
            method: "GET",
            uri: "/s?q=1%20UNION%20SELECT%20p%20FROM%20u",
            body: None,
            cookies: None,
        },
        Case {
            name: "attack, xss (blocks)",
            method: "GET",
            uri: "/s?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            body: None,
            cookies: None,
        },
    ];

    let big_json = format!("{{\"data\":\"{}\"}}", "x".repeat(4000));

    println!(
        "\n{:<28} {:>9} {:>9} {:>9} {:>9}  verdict",
        "case", "p50", "p90", "p99", "mean"
    );
    for case in &cases {
        let body_owned: Option<(&str, String)> = case.body.map(|(ct, b)| {
            (
                ct,
                if b.is_empty() {
                    big_json.clone()
                } else {
                    b.to_string()
                },
            )
        });

        // Warm up so the first-touch page faults do not land in the sample.
        for _ in 0..200 {
            run_one(&rules, case, body_owned.as_ref());
        }

        let iters = 3000;
        let mut samples = Vec::with_capacity(iters);
        let mut last = Verdict::Allow;
        for _ in 0..iters {
            let t = Instant::now();
            last = run_one(&rules, case, body_owned.as_ref());
            samples.push(t.elapsed().as_nanos());
        }
        let expected_block = case.name.starts_with("attack");
        let blocked = last != Verdict::Allow;
        assert_eq!(
            blocked, expected_block,
            "case {:?} verdict is wrong (blocked={blocked}); the measurement would be of the \
             wrong code path. Is crs-setup.conf.example present in the rules directory?",
            case.name
        );
        samples.sort_unstable();
        let pick = |p: f64| samples[((samples.len() as f64 - 1.0) * p) as usize];
        let mean = samples.iter().sum::<u128>() as f64 / samples.len() as f64;
        println!(
            "{:<28} {:>8.1}u {:>8.1}u {:>8.1}u {:>8.1}u  {}",
            case.name,
            pick(0.50) as f64 / 1000.0,
            pick(0.90) as f64 / 1000.0,
            pick(0.99) as f64 / 1000.0,
            mean / 1000.0,
            if last == Verdict::Allow {
                "allow"
            } else {
                "block"
            }
        );
    }
}

fn run_one(rules: &RuleSet, case: &Case, body: Option<&(&str, String)>) -> Verdict {
    let mut tx = Transaction::new(rules, EngineMode::Blocking);
    tx.set_tx("blocking_paranoia_level", b"1".to_vec());
    tx.set_tx("detection_paranoia_level", b"1".to_vec());
    tx.set_tx("inbound_anomaly_score_threshold", b"5".to_vec());
    tx.set_tx("outbound_anomaly_score_threshold", b"4".to_vec());
    tx.set_remote_addr(b"203.0.113.7".to_vec());
    tx.process_uri(case.method, case.uri, "HTTP/1.1");
    tx.add_request_header("Host", "example.test");
    tx.add_request_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)");
    tx.add_request_header("Accept", "text/html,application/xhtml+xml");
    if let Some(cookies) = case.cookies {
        tx.add_request_header("Cookie", cookies);
    }
    if let Some((ct, _)) = body {
        tx.add_request_header("Content-Type", ct);
    }
    let v = tx.process_request_headers();
    if v != Verdict::Allow {
        return v;
    }
    if let Some((ct, b)) = body {
        tx.set_request_body(b.as_bytes(), Some(ct));
    }
    tx.process_request_body()
}
