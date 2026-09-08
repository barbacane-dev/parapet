//! A parsed rule set survives serialisation unchanged.
//!
//! This is the interface a host uses to validate a rule set at build time and
//! seal the result into its own artifact, so the property that matters is not
//! that the bytes round-trip but that the *behaviour* does: the rule set
//! rebuilt from the serialised form must reach the same verdicts as the one
//! built from source.

#![cfg(feature = "serde")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use parapet::matcher::NoDataLoader;
use parapet::transaction::EngineMode;
use parapet::{Directive, RuleSet, Transaction, Verdict};

const RULES: &str = r#"
SecDefaultAction "phase:2,log,auditlog,pass"
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.threshold=5'"
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|ARGS_NAMES|ARGS|XML:/*|XML://@* "@rx (?i)union\s+select" \
    "id:2,phase:2,block,capture,t:none,t:urlDecodeUni,t:lowercase,\
    msg:'SQLi',logdata:'Matched %{TX.0} in %{MATCHED_VAR_NAME}',\
    tag:'attack-sqli',severity:'CRITICAL',\
    setvar:'tx.score=+5'"
SecRule REQUEST_METHOD "!@within GET HEAD POST" "id:3,phase:1,deny,status:405"
SecRule &REQUEST_HEADERS:Transfer-Encoding "@ge 1" "id:4,phase:1,pass,nolog,chain"
    SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" "t:none"
SecMarker END
SecRule TX:SCORE "@ge %{tx.threshold}" "id:5,phase:2,deny,status:403,msg:'score exceeded'"
SecRule ARGS "@validateByteRange 1-255" "id:6,phase:2,pass,nolog,setvar:'tx.score=-1',setvar:!tx.stale,ctl:ruleRemoveById=942100"
SecRule REQUEST_URI "@detectSQLi" "id:7,phase:1,pass,nolog"
"#;

fn parsed() -> Vec<Directive> {
    parapet::parse(RULES, "roundtrip.conf").expect("must parse")
}

#[test]
fn directives_round_trip_through_json() {
    let before = parsed();
    let json = serde_json::to_vec(&before).expect("must serialise");
    let after: Vec<Directive> = serde_json::from_slice(&json).expect("must deserialise");
    assert_eq!(before, after, "the AST is not preserved");
}

#[test]
fn every_construct_in_the_fixture_survives() {
    // Guards against a type gaining a field that is skipped on serialisation:
    // equality above would catch it, but only if the fixture exercises it.
    let json = serde_json::to_string(&parsed()).unwrap();
    for construct in [
        "Xml",
        "XPath",
        "Regex",
        "UrlDecodeUni",
        "Capture",
        "Chain",
        "SetVar",
        "Subtract",
        "Within",
        "ValidateByteRange",
        "DetectSqli",
        "Marker",
        "DefaultAction",
        "Critical",
        "Macro",
    ] {
        assert!(
            json.contains(construct),
            "fixture does not exercise {construct}, so the round trip does not cover it"
        );
    }
}

/// The property a host actually depends on.
#[test]
fn a_rule_set_rebuilt_from_json_behaves_identically() {
    let json = serde_json::to_vec(&parsed()).unwrap();
    let restored: Vec<Directive> = serde_json::from_slice(&json).unwrap();

    // The libinjection operator refuses to compile, so both sides use
    // compile_all and must refuse the same rules.
    let (direct, direct_errors) = RuleSet::compile_all(&parsed(), &NoDataLoader);
    let (rebuilt, rebuilt_errors) = RuleSet::compile_all(&restored, &NoDataLoader);

    assert_eq!(direct.rule_count(), rebuilt.rule_count());
    assert_eq!(direct.marker_count(), rebuilt.marker_count());
    assert_eq!(
        direct_errors.len(),
        rebuilt_errors.len(),
        "the two rule sets refuse different rules"
    );

    let cases: &[(&str, &str, Verdict)] = &[
        (
            "GET",
            "/?q=1%20UNION%20SELECT%20p%20FROM%20u",
            Verdict::Deny {
                status: 403,
                rule_id: 5,
            },
        ),
        (
            "DELETE",
            "/",
            Verdict::Deny {
                status: 405,
                rule_id: 3,
            },
        ),
        ("GET", "/?q=hello", Verdict::Allow),
    ];

    for (method, uri, expected) in cases {
        for (label, rules) in [("direct", &direct), ("rebuilt", &rebuilt)] {
            let mut tx = Transaction::new(rules, EngineMode::Blocking);
            tx.process_uri(method, uri, "HTTP/1.1");
            tx.process_request_headers();
            let verdict = tx.process_request_body();
            assert_eq!(
                &verdict, expected,
                "{label} rule set disagreed on {method} {uri}"
            );
        }
    }
}

#[test]
fn an_unknown_variant_is_rejected_rather_than_ignored() {
    // A rule set is a security control, so a serialised form the current
    // version does not fully understand must fail loudly rather than load
    // with the unrecognised part dropped.
    let json = r#"[{"Marker":"END"},{"Nonsense":{"x":1}}]"#;
    let result: Result<Vec<Directive>, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "an unrecognised directive variant deserialised successfully"
    );
}
