//! Parsing SecLang source into [`Directive`]s.
//!
//! Every construct Parapet does not implement is a parse error carrying the
//! file and line, never a skipped directive. A rule set that loses a rule it
//! could not understand has converted that rule into a bypass.

use crate::action::{Action, ActionError};
use crate::operator::{Operator, OperatorError};
use crate::rule::{Collection, Directive, Rule, Selector, Target};

/// A parse failure, located in the source.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{source_name}:{line}: {kind}")]
pub struct ParseError {
    /// The file the directive came from.
    pub source_name: String,
    /// 1-based line of the directive's first line.
    pub line: usize,
    /// What went wrong.
    pub kind: ParseErrorKind,
}

/// The kinds of parse failure.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ParseErrorKind {
    /// A directive Parapet does not implement.
    #[error("unsupported directive {name:?}")]
    UnsupportedDirective {
        /// The directive name as written.
        name: String,
    },
    /// A directive with the wrong number of arguments.
    #[error("{directive} expects {expected} arguments, found {found}")]
    Arity {
        /// The directive name.
        directive: String,
        /// How many arguments it takes.
        expected: usize,
        /// How many were given.
        found: usize,
    },
    /// A target list that could not be parsed.
    #[error("target {target:?}: {detail}")]
    Target {
        /// The offending target.
        target: String,
        /// What was wrong.
        detail: String,
    },
    /// The operator could not be parsed.
    #[error(transparent)]
    Operator(#[from] OperatorError),
    /// An action could not be parsed.
    #[error(transparent)]
    Action(#[from] ActionError),
    /// A quoted string was never closed.
    #[error("unterminated quoted string")]
    UnterminatedQuote,
}

/// Parse a SecLang source file, stopping at the first error.
///
/// This is the shape an embedder wants: a rule set that cannot be fully
/// understood is refused, and the error says where. Use [`parse_all`] for
/// tooling that needs to see every problem in one pass.
///
/// `source_name` appears in error messages and is usually the file name.
pub fn parse(source: &str, source_name: &str) -> Result<Vec<Directive>, ParseError> {
    let (directives, errors) = parse_all(source, source_name);
    match errors.into_iter().next() {
        Some(e) => Err(e),
        None => Ok(directives),
    }
}

/// Parse a SecLang source file, collecting every error.
///
/// Returns the directives that did parse alongside all failures. A caller that
/// enforces rules must treat a non-empty error list as a refusal: the
/// directives returned are an incomplete rule set, and enforcing a subset of a
/// rule set silently weakens it.
pub fn parse_all(source: &str, source_name: &str) -> (Vec<Directive>, Vec<ParseError>) {
    let mut out = Vec::new();
    let mut errors = Vec::new();
    for (line_no, text) in logical_lines(source) {
        let trimmed = text.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let err = |kind: ParseErrorKind| ParseError {
            source_name: source_name.to_string(),
            line: line_no,
            kind,
        };
        let tokens = match tokenize(trimmed) {
            Ok(t) => t,
            Err(k) => {
                errors.push(err(k));
                continue;
            }
        };
        let Some(directive) = tokens.first() else {
            continue;
        };

        let arity = |expected: usize| {
            err(ParseErrorKind::Arity {
                directive: directive.clone(),
                expected,
                found: tokens.len() - 1,
            })
        };

        match directive.as_str() {
            "SecRule" => {
                if tokens.len() != 4 && tokens.len() != 3 {
                    errors.push(arity(3));
                    continue;
                }
                let targets = match parse_targets(&tokens[1]) {
                    Ok(t) => t,
                    Err((target, detail)) => {
                        errors.push(err(ParseErrorKind::Target { target, detail }));
                        continue;
                    }
                };
                let (negated, body) = match tokens[2].strip_prefix('!') {
                    Some(rest) => (true, rest),
                    None => (false, tokens[2].as_str()),
                };
                let operator = match Operator::parse(body) {
                    Ok(o) => o,
                    Err(e) => {
                        errors.push(err(e.into()));
                        continue;
                    }
                };
                let actions = match tokens.get(3) {
                    Some(a) => match parse_actions(a) {
                        Ok(a) => a,
                        Err(e) => {
                            errors.push(err(e.into()));
                            continue;
                        }
                    },
                    None => Vec::new(),
                };
                out.push(Directive::Rule(Rule {
                    targets,
                    operator: Some(operator),
                    negated,
                    actions,
                    line: line_no,
                }));
            }
            "SecAction" => {
                if tokens.len() != 2 {
                    errors.push(arity(1));
                    continue;
                }
                let actions = match parse_actions(&tokens[1]) {
                    Ok(a) => a,
                    Err(e) => {
                        errors.push(err(e.into()));
                        continue;
                    }
                };
                out.push(Directive::Action(Rule {
                    targets: Vec::new(),
                    operator: None,
                    negated: false,
                    actions,
                    line: line_no,
                }));
            }
            "SecDefaultAction" => {
                if tokens.len() != 2 {
                    errors.push(arity(1));
                    continue;
                }
                let actions = match parse_actions(&tokens[1]) {
                    Ok(a) => a,
                    Err(e) => {
                        errors.push(err(e.into()));
                        continue;
                    }
                };
                let phase = actions
                    .iter()
                    .find_map(|a| match a {
                        Action::Phase(p) => Some(*p),
                        _ => None,
                    })
                    .unwrap_or(crate::Phase::RequestBody);
                out.push(Directive::DefaultAction { phase, actions });
            }
            "SecMarker" => {
                if tokens.len() != 2 {
                    errors.push(arity(1));
                    continue;
                }
                out.push(Directive::Marker(tokens[1].clone()));
            }
            "SecComponentSignature" => {
                if tokens.len() != 2 {
                    errors.push(arity(1));
                    continue;
                }
                out.push(Directive::ComponentSignature(tokens[1].clone()));
            }
            other => errors.push(err(ParseErrorKind::UnsupportedDirective {
                name: other.to_string(),
            })),
        }
    }
    (out, errors)
}

/// Join SecLang's backslash continuations, yielding `(first_line_number, text)`.
fn logical_lines(source: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut start = 1usize;
    for (i, raw) in source.lines().enumerate() {
        let line_no = i + 1;
        if buf.is_empty() {
            start = line_no;
        }
        let trimmed_end = raw.trim_end();
        if let Some(head) = trimmed_end.strip_suffix('\\') {
            buf.push_str(head);
            continue;
        }
        buf.push_str(trimmed_end);
        out.push((start, std::mem::take(&mut buf)));
    }
    if !buf.is_empty() {
        out.push((start, buf));
    }
    out
}

/// Split a directive into whitespace-separated tokens, honouring double quotes
/// and `\"` escapes inside them.
fn tokenize(line: &str) -> Result<Vec<String>, ParseErrorKind> {
    let chars: Vec<char> = line.chars().collect();
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if in_quotes {
            if c == '\\' && i + 1 < chars.len() && chars[i + 1] == '"' {
                cur.push('"');
                i += 2;
                continue;
            }
            if c == '"' {
                in_quotes = false;
                i += 1;
                continue;
            }
            cur.push(c);
            i += 1;
            continue;
        }
        if c == '"' {
            in_quotes = true;
            i += 1;
            continue;
        }
        if c.is_whitespace() {
            if !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
            i += 1;
            continue;
        }
        cur.push(c);
        i += 1;
    }
    if in_quotes {
        return Err(ParseErrorKind::UnterminatedQuote);
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    Ok(tokens)
}

/// Parse a pipe-separated target list such as `ARGS|!ARGS:x|&REQUEST_HEADERS:/^X-/`.
fn parse_targets(spec: &str) -> Result<Vec<Target>, (String, String)> {
    let mut out = Vec::new();
    for raw in spec.split('|') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let bad = |detail: &str| (raw.to_string(), detail.to_string());

        let mut rest = raw;
        let mut exclusion = false;
        let mut count = false;
        loop {
            match rest.chars().next() {
                Some('!') => {
                    exclusion = true;
                    rest = &rest[1..];
                }
                Some('&') => {
                    count = true;
                    rest = &rest[1..];
                }
                _ => break,
            }
        }

        let (name, raw_selector) = match rest.split_once(':') {
            Some((name, sel)) => (name, Some(sel.trim())),
            None => (rest, None),
        };

        let collection = Collection::parse(name).ok_or_else(|| {
            bad("unknown collection: Parapet implements the collections the Core Rule Set uses, and refuses rather than inspecting nothing")
        })?;

        // The selector's syntax depends on the collection. `XML` is selected
        // with XPath (`XML:/*`, `XML://@*`); every other collection uses either
        // a member name or a `/regex/` over member names.
        let selector = match raw_selector {
            None => None,
            Some(sel) if collection == Collection::Xml => {
                if !sel.starts_with('/') {
                    return Err(bad(
                        "XML selectors are XPath expressions and must start with '/'",
                    ));
                }
                Some(Selector::XPath(sel.to_string()))
            }
            Some(sel) => Some(match sel.strip_prefix('/') {
                Some(inner) => {
                    let inner = inner
                        .strip_suffix('/')
                        .ok_or_else(|| bad("regex selector is missing its closing '/'"))?;
                    Selector::Regex(inner.to_string())
                }
                None => Selector::Name(sel.trim_matches('\'').to_string()),
            }),
        };

        out.push(Target {
            collection,
            selector,
            exclusion,
            count,
        });
    }
    if out.is_empty() {
        return Err((spec.to_string(), "no targets".to_string()));
    }
    Ok(out)
}

/// Split an action list on commas that are not inside quotes or parentheses,
/// then parse each action.
fn parse_actions(spec: &str) -> Result<Vec<Action>, ActionError> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut depth = 0usize;

    for c in spec.chars() {
        match c {
            '\'' => {
                in_single = !in_single;
                cur.push(c);
            }
            '(' if !in_single => {
                depth += 1;
                cur.push(c);
            }
            ')' if !in_single => {
                depth = depth.saturating_sub(1);
                cur.push(c);
            }
            ',' if !in_single && depth == 0 => parts.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        parts.push(cur);
    }

    let mut out = Vec::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        out.push(Action::parse(part)?);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::action::Transformation;
    use crate::Phase;

    #[test]
    fn parses_a_realistic_chained_rule() {
        let src = r#"
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|ARGS_NAMES "@detectSQLi" \
    "id:942100,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Injection Attack Detected via libinjection',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}',\
    tag:'attack-sqli',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}'"
"#;
        let directives = parse(src, "test.conf").unwrap();
        assert_eq!(directives.len(), 1);
        let Directive::Rule(rule) = &directives[0] else {
            panic!("expected a rule");
        };
        assert_eq!(rule.targets.len(), 3);
        assert!(rule.targets[1].exclusion);
        assert_eq!(rule.id(), Some(942100));
        assert!(!rule.negated);
        assert!(rule
            .actions
            .contains(&Action::Transform(Transformation::UrlDecodeUni)));
        assert!(rule.actions.contains(&Action::Phase(Phase::RequestBody)));
    }

    #[test]
    fn continuation_lines_report_the_first_line() {
        let src = "# comment\n\nSecRule ARGS \"@detectXSS\" \\\n    \"id:1,phase:2\"\n";
        let directives = parse(src, "t.conf").unwrap();
        let Directive::Rule(rule) = &directives[0] else {
            panic!("expected a rule");
        };
        assert_eq!(rule.line, 3);
    }

    #[test]
    fn parses_negated_operators() {
        let src = "SecRule REQUEST_METHOD \"!@within GET POST\" \"id:2,phase:1,deny\"\n";
        let Directive::Rule(rule) = &parse(src, "t.conf").unwrap()[0] else {
            panic!("expected a rule");
        };
        assert!(rule.negated);
    }

    #[test]
    fn parses_regex_and_name_selectors() {
        let src = "SecRule REQUEST_HEADERS:/^X-/|ARGS:username \"@rx x\" \"id:3,phase:1\"\n";
        let Directive::Rule(rule) = &parse(src, "t.conf").unwrap()[0] else {
            panic!("expected a rule");
        };
        assert_eq!(
            rule.targets[0].selector,
            Some(Selector::Regex("^X-".into()))
        );
        assert_eq!(
            rule.targets[1].selector,
            Some(Selector::Name("username".into()))
        );
    }

    #[test]
    fn parses_markers_and_secaction() {
        let src = "SecMarker END-REQUEST-942\nSecAction \"id:4,phase:1,pass,nolog\"\n";
        let d = parse(src, "t.conf").unwrap();
        assert_eq!(d[0], Directive::Marker("END-REQUEST-942".into()));
        let Directive::Action(rule) = &d[1] else {
            panic!("expected SecAction");
        };
        assert!(rule.operator.is_none());
        assert!(rule.targets.is_empty());
    }

    #[test]
    fn commas_inside_quoted_arguments_do_not_split_actions() {
        let src = "SecRule ARGS \"@rx x\" \"id:5,phase:2,msg:'one, two, three',nolog\"\n";
        let Directive::Rule(rule) = &parse(src, "t.conf").unwrap()[0] else {
            panic!("expected a rule");
        };
        assert!(rule
            .actions
            .contains(&Action::Msg("one, two, three".into())));
    }

    #[test]
    fn escaped_quotes_survive_tokenizing() {
        let toks = tokenize(r#"SecRule ARGS "@rx \"quoted\"" "id:6""#).unwrap();
        assert_eq!(toks[2], r#"@rx "quoted""#);
    }

    #[test]
    fn unknown_directive_is_an_error() {
        let err = parse("SecWhatever on\n", "t.conf").unwrap_err();
        assert!(matches!(
            err.kind,
            ParseErrorKind::UnsupportedDirective { .. }
        ));
        assert_eq!(err.line, 1);
    }

    #[test]
    fn unknown_collection_is_an_error() {
        let err = parse("SecRule NOT_A_THING \"@rx x\" \"id:7\"\n", "t.conf").unwrap_err();
        match err.kind {
            ParseErrorKind::Target { detail, .. } => {
                assert!(detail.contains("inspecting nothing"))
            }
            other => panic!("expected a target error, got {other:?}"),
        }
    }

    #[test]
    fn unterminated_quote_is_an_error() {
        let err = parse("SecRule ARGS \"@rx x\" \"id:8\n", "t.conf").unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::UnterminatedQuote);
    }

    #[test]
    fn sec_rule_arity_is_enforced() {
        assert!(matches!(
            parse("SecRule ARGS\n", "t").unwrap_err().kind,
            ParseErrorKind::Arity { .. }
        ));
    }

    #[test]
    fn a_bad_operator_or_action_in_a_secrule_is_reported() {
        assert!(matches!(
            parse("SecRule ARGS \"@nope x\" \"id:1\"\n", "t")
                .unwrap_err()
                .kind,
            ParseErrorKind::Operator(_)
        ));
        assert!(matches!(
            parse("SecRule ARGS \"@rx x\" \"id:notanumber\"\n", "t")
                .unwrap_err()
                .kind,
            ParseErrorKind::Action(_)
        ));
    }

    #[test]
    fn a_three_token_secrule_without_actions_parses() {
        let d = parse("SecRule ARGS \"@rx x\"\n", "t").unwrap();
        let Directive::Rule(rule) = &d[0] else {
            panic!("expected a rule");
        };
        assert!(rule.actions.is_empty());
    }

    #[test]
    fn xml_and_regex_selector_syntax_is_validated() {
        // An XML selector must be an XPath starting with '/'.
        assert!(matches!(
            parse("SecRule XML:notxpath \"@rx x\" \"id:1\"\n", "t")
                .unwrap_err()
                .kind,
            ParseErrorKind::Target { .. }
        ));
        // A regex selector must close its slash.
        assert!(matches!(
            parse("SecRule ARGS:/open \"@rx x\" \"id:1\"\n", "t")
                .unwrap_err()
                .kind,
            ParseErrorKind::Target { .. }
        ));
        // Empty members between pipes are skipped, not an error.
        let d = parse("SecRule ARGS||REQUEST_URI \"@rx x\" \"id:1\"\n", "t").unwrap();
        let Directive::Rule(rule) = &d[0] else {
            panic!()
        };
        assert_eq!(rule.targets.len(), 2);
    }

    #[test]
    fn an_empty_target_list_is_an_error() {
        assert!(parse("SecRule | \"@rx x\" \"id:1\"\n", "t").is_err());
    }

    #[test]
    fn secaction_arity_and_action_errors_are_reported() {
        assert!(matches!(
            parse("SecAction a b\n", "t").unwrap_err().kind,
            ParseErrorKind::Arity { .. }
        ));
        assert!(matches!(
            parse("SecAction \"id:notnum\"\n", "t").unwrap_err().kind,
            ParseErrorKind::Action(_)
        ));
    }

    #[test]
    fn secdefaultaction_parses_and_defaults_its_phase() {
        // No phase given: defaults to phase 2.
        let d = parse("SecDefaultAction \"pass,log\"\n", "t").unwrap();
        assert!(matches!(
            &d[0],
            Directive::DefaultAction { phase, .. } if *phase == Phase::RequestBody
        ));
        assert!(parse("SecDefaultAction\n", "t").is_err());
        assert!(parse("SecDefaultAction \"bogus:1\"\n", "t").is_err());
    }

    #[test]
    fn secmarker_and_component_signature_arity_is_enforced() {
        assert!(parse("SecMarker\n", "t").is_err());
        let d = parse("SecComponentSignature \"OWASP_CRS/4.0.0\"\n", "t").unwrap();
        assert_eq!(
            d[0],
            Directive::ComponentSignature("OWASP_CRS/4.0.0".into())
        );
        assert!(parse("SecComponentSignature\n", "t").is_err());
    }

    #[test]
    fn a_paren_group_protects_commas_inside_an_action_list() {
        let d = parse("SecAction \"id:1,setvar:tx.x=(a,b),pass\"\n", "t").unwrap();
        let Directive::Action(rule) = &d[0] else {
            panic!()
        };
        // id, setvar, pass -> the comma inside (a,b) did not split.
        assert_eq!(rule.actions.len(), 3);
    }

    #[test]
    fn a_trailing_continuation_still_yields_its_directive() {
        // The last logical line ends on a continuation with no newline after.
        let d = parse("SecAction \"id:1,pass\" \\", "t").unwrap();
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn error_messages_carry_file_and_line() {
        let err = parse("\n\nSecBogus x\n", "rules/REQUEST-942.conf").unwrap_err();
        assert_eq!(
            err.to_string(),
            "rules/REQUEST-942.conf:3: unsupported directive \"SecBogus\""
        );
    }
}
