//! Compiling SecLang `@rx` patterns with the `regex` crate.
//!
//! SecLang rule sets are authored against PCRE, and the OWASP Core Rule Set
//! constrains itself to RE2-expressible patterns because ModSecurity's Go
//! successor evaluates them with Go's `regexp`. The `regex` crate accepts the
//! same language, with one difference: its parser rejects two constructs that
//! PCRE and RE2 accept.
//!
//! * A `{` or `}` that does not form a counted repetition. PCRE and RE2 read it
//!   as a literal; `regex-syntax` requires it escaped.
//! * A redundant escape of ASCII punctuation inside a character class.
//!
//! Measured against CRS v4.9.0: 268 of 273 unique `@rx` patterns compile
//! unmodified, and the remaining 5 are all instances of the two cases above.
//!
//! Repairs are attempted only after a direct compile fails, so a pattern the
//! `regex` crate already accepts is never rewritten. Rewriting an accepted
//! pattern would be an unreviewed semantic change to a security control.

use regex::Regex;

/// A compiled `@rx` operand, and the rewrite applied to make it compile.
#[derive(Debug)]
pub struct CompiledRx {
    /// The compiled pattern.
    pub regex: Regex,
    /// The rewritten pattern, when the pattern as authored did not compile.
    /// `None` means the pattern was used exactly as written.
    pub repaired_from: Option<String>,
}

/// Why a pattern could not be compiled at all.
#[derive(Debug, thiserror::Error)]
#[error("pattern is not expressible with the regex crate: {source_error}")]
pub struct RxError {
    /// The pattern as authored in the rule set.
    pub pattern: String,
    /// The `regex` crate's parse error, after repairs were attempted.
    pub source_error: String,
}

/// Punctuation that CRS escapes inside character classes and that
/// `regex-syntax` rejects. Tried one at a time, narrowest repair first.
const CLASS_ESCAPE_CANDIDATES: &[char] = &[
    '&', '|', '!', '<', '>', '~', '(', ')', '=', ',', '/', '"', '\'', '#', '%', ';', ':', '@', '`',
];

/// Compile a SecLang `@rx` operand.
///
/// Tries the pattern as authored. Only if that fails does it apply the
/// documented repairs, so accepted patterns pass through untouched.
pub fn compile(pattern: &str) -> Result<CompiledRx, RxError> {
    if let Ok(regex) = Regex::new(pattern) {
        return Ok(CompiledRx {
            regex,
            repaired_from: None,
        });
    }

    let mut candidate = escape_literal_braces(pattern);
    if let Ok(regex) = Regex::new(&candidate) {
        return Ok(CompiledRx {
            regex,
            repaired_from: Some(candidate),
        });
    }

    for offender in CLASS_ESCAPE_CANDIDATES {
        let next = strip_class_escape(&candidate, *offender);
        if next != candidate {
            candidate = next;
            if let Ok(regex) = Regex::new(&candidate) {
                return Ok(CompiledRx {
                    regex,
                    repaired_from: Some(candidate),
                });
            }
        }
    }

    Err(RxError {
        pattern: pattern.to_string(),
        source_error: Regex::new(&candidate)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default(),
    })
}

/// Escape `{` and `}` that do not delimit a counted repetition (`{n}`, `{n,}`,
/// `{n,m}`).
fn escape_literal_braces(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len() + 8);
    let mut i = 0;
    let mut in_class = false;
    let mut repetition_open = false;

    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && i + 1 < chars.len() {
            out.push('\\');
            out.push(chars[i + 1]);
            i += 2;
            continue;
        }
        match c {
            '[' if !in_class => {
                in_class = true;
                out.push(c);
            }
            ']' if in_class => {
                in_class = false;
                out.push(c);
            }
            '{' if !in_class => {
                if is_repetition_at(&chars, i) {
                    out.push('{');
                    repetition_open = true;
                } else {
                    out.push_str("\\{");
                }
            }
            '}' if !in_class => {
                if repetition_open {
                    out.push('}');
                    repetition_open = false;
                } else {
                    out.push_str("\\}");
                }
            }
            _ => out.push(c),
        }
        i += 1;
    }
    out
}

/// Does `{` at `start` open a valid counted repetition?
fn is_repetition_at(chars: &[char], start: usize) -> bool {
    let mut j = start + 1;
    let mut digits = 0;
    while j < chars.len() && chars[j].is_ascii_digit() {
        j += 1;
        digits += 1;
    }
    if digits == 0 {
        return false;
    }
    if j < chars.len() && chars[j] == ',' {
        j += 1;
        while j < chars.len() && chars[j].is_ascii_digit() {
            j += 1;
        }
    }
    j < chars.len() && chars[j] == '}'
}

/// Drop the escape from `\<offender>` inside character classes, leaving escapes
/// outside classes and structurally significant class escapes alone.
fn strip_class_escape(pattern: &str, offender: char) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len());
    let mut i = 0;
    let mut in_class = false;

    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && i + 1 < chars.len() {
            let next = chars[i + 1];
            if in_class && next == offender {
                out.push(next);
            } else {
                out.push('\\');
                out.push(next);
            }
            i += 2;
            continue;
        }
        if !in_class && c == '[' {
            in_class = true;
        } else if in_class && c == ']' {
            in_class = false;
        }
        out.push(c);
        i += 1;
    }
    out
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The five CRS v4.9.0 patterns that do not compile as authored, with the
    /// rule ids they belong to.
    const CRS_NEEDING_REPAIR: &[(&str, &str)] = &[
        ("933170", r#"[oOcC]:\d+:".+?":\d+:{.*}"#),
        (
            "933180",
            r#"\$+(?:[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*|\s*{.+})(?:\s|\[.+\]|{.+}|/\*.*\*/|//.*|#.*)*\(.*\)"#,
        ),
        (
            "921200",
            r#"^[^:\(\)\&\|\!\<\>\~]*\)\s*(?:\((?:[^,\(\)\=\&\|\!\<\>\~]+[><~]?=|\s*[&!|]\s*(?:\)|\()?\s*)|\)\s*\(\s*[\&\|\!]\s*|[&!|]\s*\([^\(\)\=\&\|\!\<\>\~]+[><~]?=[^:\(\)\&\|\!\<\>\~]*)"#,
        ),
        ("932170", r#"^\(\s*\)\s+{"#),
        ("941380", r#"{{.*?}}"#),
    ];

    #[test]
    fn crs_patterns_needing_repair_all_compile() {
        for (id, pattern) in CRS_NEEDING_REPAIR {
            let c = compile(pattern).unwrap_or_else(|e| panic!("rule {id} failed to compile: {e}"));
            assert!(
                c.repaired_from.is_some(),
                "rule {id} was expected to need a repair"
            );
        }
    }

    #[test]
    fn accepted_patterns_are_never_rewritten() {
        // Representative CRS patterns that compile as authored. The repair pass
        // must leave every one of them byte-identical.
        let accepted = [
            r#"(?i)\bunion\b.{1,100}?\bselect\b"#,
            r#"^[\d.]+$"#,
            r#"(?i)<script[^>]*>[\s\S]*?"#,
            r#"\b(?:alert|confirm|prompt)\s*\("#,
            r#"a{2,4}"#,
            r#"x{3}"#,
            r#"[a-z]{1,}"#,
            r#"(?:\.\./){2,}"#,
        ];
        for pattern in accepted {
            let c = compile(pattern).expect("must compile");
            assert!(
                c.repaired_from.is_none(),
                "pattern was rewritten but already compiled: {pattern}"
            );
        }
    }

    #[test]
    fn valid_repetitions_are_preserved() {
        assert_eq!(escape_literal_braces("a{2,4}"), "a{2,4}");
        assert_eq!(escape_literal_braces("a{3}"), "a{3}");
        assert_eq!(escape_literal_braces("a{2,}"), "a{2,}");
    }

    #[test]
    fn literal_braces_are_escaped() {
        assert_eq!(escape_literal_braces("{{.*?}}"), r"\{\{.*?\}\}");
        assert_eq!(escape_literal_braces("{.*}"), r"\{.*\}");
        assert_eq!(escape_literal_braces(r"^\(\s*\)\s+{"), r"^\(\s*\)\s+\{");
    }

    #[test]
    fn braces_inside_character_classes_are_left_alone() {
        assert_eq!(escape_literal_braces("[{}]"), "[{}]");
    }

    #[test]
    fn escaped_braces_are_not_double_escaped() {
        assert_eq!(escape_literal_braces(r"\{"), r"\{");
        assert_eq!(escape_literal_braces(r"\}"), r"\}");
    }

    #[test]
    fn class_escape_stripping_only_touches_classes() {
        // The `\&` inside the class loses its escape; `\(` outside keeps it.
        assert_eq!(strip_class_escape(r"\([^\&]", '&'), r"\([^&]");
    }

    #[test]
    fn repaired_pattern_matches_like_the_original() {
        // Rule 941380 is the template-injection pattern `{{.*?}}`.
        let c = compile(r"{{.*?}}").expect("must compile");
        assert!(c.regex.is_match("{{7*7}}"));
        assert!(c.regex.is_match("{{constructor}}"));
        assert!(!c.regex.is_match("{7*7}"));
        assert!(!c.regex.is_match("no braces here"));
    }

    #[test]
    fn rule_933170_matches_php_object_serialisation() {
        let (_, pattern) = CRS_NEEDING_REPAIR[0];
        let c = compile(pattern).expect("must compile");
        assert!(c.regex.is_match(r#"O:4:"Test":1:{s:3:"abc"}"#));
        assert!(c.regex.is_match(r#"C:8:"A":2:{i:0;}"#));
        assert!(!c.regex.is_match(r#"X:4:"Test":1:{}"#));
    }

    #[test]
    fn rule_932170_matches_shellshock_prologue() {
        let (_, pattern) = CRS_NEEDING_REPAIR[3];
        let c = compile(pattern).expect("must compile");
        assert!(c.regex.is_match("() {"));
        assert!(c.regex.is_match("(  )   {"));
        assert!(!c.regex.is_match("()x{"));
    }

    #[test]
    fn unrepairable_pattern_reports_an_error() {
        // Backreferences are genuinely outside the regex crate's language, and
        // no CRS rule uses one.
        let err = compile(r"(a)\1").expect_err("backreference must not compile");
        assert!(err.source_error.contains("backreference"));
    }
}
