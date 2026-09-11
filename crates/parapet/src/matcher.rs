//! Compiled operators: turning a parsed [`Operator`] into something evaluable.
//!
//! Compilation is where the expensive work happens (building regex programs
//! and Aho-Corasick automata), and it happens once. Evaluation borrows the
//! result. An embedder that compiles ahead of time pays nothing per request.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::bytes::Regex as BytesRegex;

use crate::macros::{MacroContext, Template};
use crate::operator::{Numeric, Operator};

/// Supplies the contents of `@pmFromFile` data files during compilation.
///
/// A trait rather than direct filesystem access so an embedder without a
/// filesystem, or one that vendors its rule data, stays in control of what the
/// compiler can read.
pub trait DataLoader {
    /// Load a data file by the name written in the rule.
    fn load(&self, name: &str) -> Result<Vec<u8>, String>;
}

/// A loader that reads from a directory.
pub struct DirDataLoader {
    root: std::path::PathBuf,
}

impl DirDataLoader {
    /// Read data files from `root`.
    pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
        DirDataLoader { root: root.into() }
    }
}

impl DataLoader for DirDataLoader {
    fn load(&self, name: &str) -> Result<Vec<u8>, String> {
        // A rule must not reach outside the data directory.
        if name.contains("..") || name.starts_with('/') {
            return Err(format!(
                "refusing to load {name:?}: path escapes the data directory"
            ));
        }
        let path = self.root.join(name);
        std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))
    }
}

/// A loader with no data available. Every load fails.
pub struct NoDataLoader;

impl DataLoader for NoDataLoader {
    fn load(&self, name: &str) -> Result<Vec<u8>, String> {
        Err(format!(
            "no data loader configured, so @pmFromFile {name:?} cannot be resolved"
        ))
    }
}

/// Why an operator could not be compiled.
#[derive(Debug, thiserror::Error)]
pub enum OperatorCompileError {
    /// The operator is parsed but has no implementation yet.
    ///
    /// Deliberately an error. Compiling it to something that never matches
    /// would turn the rule into a bypass with no signal.
    #[error("operator @{name} is not implemented yet: {detail}")]
    NotImplemented {
        /// The operator name.
        name: &'static str,
        /// What is missing.
        detail: &'static str,
    },
    /// The `@rx` pattern could not be compiled.
    #[error("operator @rx: {0}")]
    Regex(String),
    /// A `@pmFromFile` data file could not be loaded.
    #[error("operator @pmFromFile: {0}")]
    DataFile(String),
    /// An `@ipMatch` operand could not be parsed.
    #[error("operator @ipMatch: {0}")]
    IpAddress(String),
    /// The operand was otherwise unusable.
    #[error("operator @{name}: {detail}")]
    BadOperand {
        /// The operator name.
        name: &'static str,
        /// What was wrong.
        detail: String,
    },
}

/// A numeric comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum NumericCmp {
    Lt,
    Gt,
    Eq,
    Ge,
}

/// One entry of an `@ipMatch` list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpRange {
    address: IpAddr,
    prefix: u8,
}

impl IpRange {
    fn parse(spec: &str) -> Result<Self, String> {
        let spec = spec.trim();
        let (addr_part, prefix_part) = match spec.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (spec, None),
        };
        let address: IpAddr = addr_part
            .parse()
            .map_err(|_| format!("{addr_part:?} is not an IP address"))?;
        let max = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_part {
            Some(p) => p
                .trim()
                .parse::<u8>()
                .map_err(|_| format!("{p:?} is not a prefix length"))?,
            None => max,
        };
        if prefix > max {
            return Err(format!("prefix /{prefix} is too long for {address}"));
        }
        Ok(IpRange { address, prefix })
    }

    fn contains(&self, candidate: IpAddr) -> bool {
        match (self.address, candidate) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix)
            }
            // A v4-mapped v6 address is compared as v4, so a rule written for
            // one family still matches a client presented as the other.
            (IpAddr::V4(net), IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
                Some(v4) => prefix_eq(&net.octets(), &v4.octets(), self.prefix),
                None => false,
            },
            (IpAddr::V6(net), IpAddr::V4(ip)) => match net.to_ipv4_mapped() {
                Some(v4) => prefix_eq(&v4.octets(), &ip.octets(), self.prefix.saturating_sub(96)),
                None => false,
            },
        }
    }
}

fn prefix_eq(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let whole = (prefix / 8) as usize;
    let bits = prefix % 8;
    if a[..whole] != b[..whole] {
        return false;
    }
    if bits == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - bits);
    a.get(whole).map(|x| x & mask) == b.get(whole).map(|x| x & mask)
}

/// The result of evaluating an operator.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OperatorMatch {
    /// Whether the operator matched, before any `!` negation is applied.
    pub matched: bool,
    /// Regex capture groups, populated only when the rule asked to `capture`.
    /// Index 0 is the whole match, as SecLang exposes it in `TX:0`.
    pub captures: Vec<Vec<u8>>,
}

impl OperatorMatch {
    fn plain(matched: bool) -> Self {
        OperatorMatch {
            matched,
            captures: Vec::new(),
        }
    }
}

/// An operator ready to evaluate.
#[derive(Debug)]
pub enum CompiledOperator {
    /// `@rx`, compiled over bytes so a non-UTF-8 subject can still be matched.
    Rx(BytesRegex),
    /// `@pm` and `@pmFromFile`, which share an implementation.
    ///
    /// `min_len` is the shortest pattern: a subject shorter than that cannot
    /// match, so the automaton is skipped.
    Pm {
        /// The multi-pattern automaton.
        matcher: Box<AhoCorasick>,
        /// Length of the shortest pattern.
        min_len: usize,
    },
    /// `@streq`
    Streq(Template),
    /// `@contains`
    Contains(Template),
    /// `@endsWith`
    EndsWith(Template),
    /// `@within`: the subject must appear inside the operand.
    Within(Template),
    /// `@ipMatch`
    IpMatch(Vec<IpRange>),
    /// `@lt`, `@gt`, `@eq`, `@ge`
    Numeric {
        /// Which comparison.
        cmp: NumericCmp,
        /// The right-hand operand.
        operand: Numeric,
    },
    /// `@validateByteRange`: matches when any byte falls outside the allowed set.
    ValidateByteRange(Box<[bool; 256]>),
    /// `@validateUtf8Encoding`: matches when the subject is not valid UTF-8.
    ValidateUtf8Encoding,
    /// `@validateUrlEncoding`: matches when percent-encoding is malformed.
    ValidateUrlEncoding,
    /// `@unconditionalMatch`
    UnconditionalMatch,
    /// `@detectSQLi`: libinjection SQL injection classifier.
    DetectSqli,
    /// `@detectXSS`: libinjection cross-site scripting classifier.
    DetectXss,
}

impl CompiledOperator {
    /// Compile a parsed operator.
    pub fn compile(
        operator: &Operator,
        loader: &dyn DataLoader,
    ) -> Result<Self, OperatorCompileError> {
        Ok(match operator {
            Operator::Rx(pattern) => {
                let compiled = crate::regex_compat::compile(pattern)
                    .map_err(|e| OperatorCompileError::Regex(e.source_error))?;
                // regex_compat validated the pattern (and repaired it if
                // needed); rebuild it over bytes for matching.
                let source = compiled
                    .repaired_from
                    .unwrap_or_else(|| pattern.to_string());
                BytesRegex::new(&source)
                    .map(CompiledOperator::Rx)
                    .map_err(|e| OperatorCompileError::Regex(e.to_string()))?
            }
            Operator::Pm(phrases) => build_pm(phrases.iter().map(String::as_str))?,
            Operator::PmFromFile(name) => {
                let raw = loader.load(name).map_err(OperatorCompileError::DataFile)?;
                let text = String::from_utf8_lossy(&raw).into_owned();
                let phrases: Vec<&str> = text
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .collect();
                build_pm(phrases.into_iter())?
            }
            Operator::Streq(s) => CompiledOperator::Streq(Template::parse(s)),
            Operator::Contains(s) => CompiledOperator::Contains(Template::parse(s)),
            Operator::EndsWith(s) => CompiledOperator::EndsWith(Template::parse(s)),
            Operator::Within(s) => CompiledOperator::Within(Template::parse(s)),
            Operator::IpMatch(list) => {
                let mut ranges = Vec::new();
                for entry in list.split(',') {
                    let entry = entry.trim();
                    if entry.is_empty() {
                        continue;
                    }
                    ranges.push(IpRange::parse(entry).map_err(OperatorCompileError::IpAddress)?);
                }
                if ranges.is_empty() {
                    return Err(OperatorCompileError::BadOperand {
                        name: "ipMatch",
                        detail: "no addresses".into(),
                    });
                }
                CompiledOperator::IpMatch(ranges)
            }
            Operator::Lt(n) => CompiledOperator::Numeric {
                cmp: NumericCmp::Lt,
                operand: n.clone(),
            },
            Operator::Gt(n) => CompiledOperator::Numeric {
                cmp: NumericCmp::Gt,
                operand: n.clone(),
            },
            Operator::Eq(n) => CompiledOperator::Numeric {
                cmp: NumericCmp::Eq,
                operand: n.clone(),
            },
            Operator::Ge(n) => CompiledOperator::Numeric {
                cmp: NumericCmp::Ge,
                operand: n.clone(),
            },
            Operator::ValidateByteRange(ranges) => {
                let mut allowed = Box::new([false; 256]);
                for (lo, hi) in ranges {
                    for b in *lo..=*hi {
                        allowed[b as usize] = true;
                    }
                }
                CompiledOperator::ValidateByteRange(allowed)
            }
            Operator::ValidateUtf8Encoding => CompiledOperator::ValidateUtf8Encoding,
            Operator::ValidateUrlEncoding => CompiledOperator::ValidateUrlEncoding,
            Operator::UnconditionalMatch => CompiledOperator::UnconditionalMatch,
            Operator::DetectSqli => CompiledOperator::DetectSqli,
            Operator::DetectXss => CompiledOperator::DetectXss,
        })
    }

    /// Evaluate against one target value.
    ///
    /// `capture` requests regex capture groups; it is ignored by operators
    /// that cannot produce them.
    pub fn evaluate(&self, subject: &[u8], ctx: &dyn MacroContext, capture: bool) -> OperatorMatch {
        match self {
            CompiledOperator::Rx(re) => {
                if capture {
                    match re.captures(subject) {
                        Some(caps) => OperatorMatch {
                            matched: true,
                            captures: caps
                                .iter()
                                .map(|m| m.map(|m| m.as_bytes().to_vec()).unwrap_or_default())
                                .collect(),
                        },
                        None => OperatorMatch::plain(false),
                    }
                } else {
                    OperatorMatch::plain(re.is_match(subject))
                }
            }
            CompiledOperator::Pm { matcher, min_len } => {
                if subject.len() < *min_len {
                    return OperatorMatch::plain(false);
                }
                OperatorMatch::plain(matcher.is_match(subject))
            }
            CompiledOperator::Streq(t) => OperatorMatch::plain(t.expand(ctx).as_ref() == subject),
            CompiledOperator::Contains(t) => {
                OperatorMatch::plain(contains(subject, t.expand(ctx).as_ref()))
            }
            CompiledOperator::EndsWith(t) => {
                OperatorMatch::plain(subject.ends_with(t.expand(ctx).as_ref()))
            }
            // Note the direction: the subject must be found inside the
            // operand, not the other way round.
            CompiledOperator::Within(t) => {
                OperatorMatch::plain(contains(t.expand(ctx).as_ref(), subject))
            }
            CompiledOperator::IpMatch(ranges) => {
                let Ok(text) = std::str::from_utf8(subject) else {
                    return OperatorMatch::plain(false);
                };
                let Ok(ip) = parse_ip(text.trim()) else {
                    return OperatorMatch::plain(false);
                };
                OperatorMatch::plain(ranges.iter().any(|r| r.contains(ip)))
            }
            CompiledOperator::Numeric { cmp, operand } => {
                let left = parse_i64(subject);
                let right = match operand {
                    Numeric::Literal(v) => Some(*v),
                    Numeric::Macro(name) => ctx
                        .lookup(name)
                        .and_then(|v| parse_i64(&v))
                        // An unset variable is 0 in SecLang, not an error.
                        .or(Some(0)),
                };
                let matched = match (left, right) {
                    (Some(l), Some(r)) => match cmp {
                        NumericCmp::Lt => l < r,
                        NumericCmp::Gt => l > r,
                        NumericCmp::Eq => l == r,
                        NumericCmp::Ge => l >= r,
                    },
                    _ => false,
                };
                OperatorMatch::plain(matched)
            }
            CompiledOperator::ValidateByteRange(allowed) => {
                if subject.is_empty() {
                    return OperatorMatch::plain(false);
                }
                OperatorMatch::plain(subject.iter().any(|b| !allowed[*b as usize]))
            }
            CompiledOperator::ValidateUtf8Encoding => {
                OperatorMatch::plain(std::str::from_utf8(subject).is_err())
            }
            CompiledOperator::ValidateUrlEncoding => {
                if subject.is_empty() {
                    return OperatorMatch::plain(false);
                }
                OperatorMatch::plain(!url_encoding_is_valid(subject))
            }
            CompiledOperator::UnconditionalMatch => OperatorMatch::plain(true),
            CompiledOperator::DetectSqli => {
                let result = libinjectionrs::detect_sqli(subject);
                if !result.is_injection() {
                    return OperatorMatch::plain(false);
                }
                if capture {
                    // ModSecurity places the fingerprint in the first capture.
                    let fp = result
                        .fingerprint
                        .as_ref()
                        .map(|f| f.as_str().as_bytes().to_vec())
                        .unwrap_or_default();
                    OperatorMatch {
                        matched: true,
                        captures: vec![fp],
                    }
                } else {
                    OperatorMatch::plain(true)
                }
            }
            CompiledOperator::DetectXss => {
                OperatorMatch::plain(libinjectionrs::detect_xss(subject).is_injection())
            }
        }
    }
}

fn build_pm<'a>(
    phrases: impl Iterator<Item = &'a str>,
) -> Result<CompiledOperator, OperatorCompileError> {
    let patterns: Vec<String> = phrases
        .filter(|p| !p.is_empty())
        .map(|p| p.to_ascii_lowercase())
        .collect();
    if patterns.is_empty() {
        return Err(OperatorCompileError::BadOperand {
            name: "pm",
            detail: "no phrases".into(),
        });
    }
    let min_len = patterns.iter().map(String::len).min().unwrap_or(0);
    let matcher = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostLongest)
        .build(&patterns)
        .map_err(|e| OperatorCompileError::BadOperand {
            name: "pm",
            detail: e.to_string(),
        })?;
    Ok(CompiledOperator::Pm {
        matcher: Box::new(matcher),
        min_len,
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Parse an address, tolerating a `[v6]` form and a `host:port` suffix, since
/// `REMOTE_ADDR` is not always a bare address.
fn parse_ip(text: &str) -> Result<IpAddr, ()> {
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Ok(ip);
    }
    if let Some(inner) = text.strip_prefix('[').and_then(|t| t.split(']').next()) {
        if let Ok(ip) = inner.parse::<Ipv6Addr>() {
            return Ok(IpAddr::V6(ip));
        }
    }
    if let Some((host, _port)) = text.rsplit_once(':') {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Ok(IpAddr::V4(ip));
        }
    }
    Err(())
}

/// Parse a leading integer, as SecLang's numeric operators do. A value with
/// trailing text compares on its numeric prefix.
fn parse_i64(bytes: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(bytes).ok()?.trim();
    if text.is_empty() {
        return Some(0);
    }
    let mut end = 0;
    for (i, c) in text.char_indices() {
        if c.is_ascii_digit() || (i == 0 && (c == '-' || c == '+')) {
            end = i + c.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 {
        return Some(0);
    }
    text[..end].parse().ok()
}

/// Whether every `%` in the input introduces a complete two-hex-digit escape.
fn url_encoding_is_valid(input: &[u8]) -> bool {
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'%' {
            i += 1;
            continue;
        }
        if i + 2 >= input.len() {
            return false;
        }
        if !input[i + 1].is_ascii_hexdigit() || !input[i + 2].is_ascii_hexdigit() {
            return false;
        }
        i += 3;
    }
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::macros::EmptyContext;
    use crate::operator::Operator;
    use std::borrow::Cow;
    use std::collections::HashMap;

    struct Vars(HashMap<String, Vec<u8>>);

    impl MacroContext for Vars {
        fn lookup(&self, name: &str) -> Option<Cow<'_, [u8]>> {
            self.0
                .get(&name.to_ascii_lowercase())
                .map(|v| Cow::Borrowed(v.as_slice()))
        }
    }

    fn vars(pairs: &[(&str, &str)]) -> Vars {
        Vars(
            pairs
                .iter()
                .map(|(k, v)| (k.to_ascii_lowercase(), v.as_bytes().to_vec()))
                .collect(),
        )
    }

    fn compile(spec: &str) -> CompiledOperator {
        let op = Operator::parse(spec).expect("operator must parse");
        CompiledOperator::compile(&op, &NoDataLoader).expect("operator must compile")
    }

    fn matches(spec: &str, subject: &str) -> bool {
        compile(spec)
            .evaluate(subject.as_bytes(), &EmptyContext, false)
            .matched
    }

    #[test]
    fn rx_matches_over_bytes() {
        assert!(matches(r"@rx (?i)union\s+select", "1 UNION  SELECT x"));
        assert!(!matches(r"@rx ^\d+$", "12a"));
    }

    #[test]
    fn rx_matches_a_non_utf8_subject() {
        // A byte regex must not refuse invalid UTF-8, which is exactly what a
        // WAF receives when someone is trying to slip past it.
        let op = compile(r"@rx abc");
        let subject = [0xff, b'a', b'b', b'c', 0xfe];
        assert!(op.evaluate(&subject, &EmptyContext, false).matched);
    }

    #[test]
    fn rx_populates_captures_only_when_asked() {
        let op = compile(r"@rx (\d+)-(\d+)");
        let without = op.evaluate(b"10-20", &EmptyContext, false);
        assert!(without.matched);
        assert!(without.captures.is_empty());

        let with = op.evaluate(b"10-20", &EmptyContext, true);
        assert_eq!(with.captures.len(), 3);
        assert_eq!(with.captures[0], b"10-20");
        assert_eq!(with.captures[1], b"10");
        assert_eq!(with.captures[2], b"20");
    }

    #[test]
    fn rx_compiles_a_pattern_needing_repair() {
        // 941380's template-injection pattern, which needs brace escaping.
        let op = compile(r"@rx {{.*?}}");
        assert!(op.evaluate(b"{{7*7}}", &EmptyContext, false).matched);
    }

    #[test]
    fn pm_is_case_insensitive_and_substring() {
        assert!(matches("@pm select union", "1 SeLeCt 2"));
        assert!(matches("@pm etc/passwd", "/../etc/passwd"));
        assert!(!matches("@pm select union", "nothing here"));
    }

    #[test]
    fn pm_short_circuits_on_short_subjects() {
        let op = compile("@pm abcdef");
        assert!(!op.evaluate(b"abc", &EmptyContext, false).matched);
        assert!(op.evaluate(b"xxabcdefxx", &EmptyContext, false).matched);
    }

    #[test]
    fn string_operators_do_what_they_say() {
        assert!(matches("@streq GET", "GET"));
        assert!(!matches("@streq GET", "GETX"));
        assert!(matches("@contains passwd", "/etc/passwd"));
        assert!(matches("@endsWith .php", "/index.php"));
        assert!(!matches("@endsWith .php", "/index.php7"));
    }

    #[test]
    fn within_looks_for_the_subject_inside_the_operand() {
        // The direction is the opposite of @contains, which is easy to invert
        // and would silently allow every method.
        assert!(matches("@within GET HEAD POST", "GET"));
        assert!(!matches("@within GET HEAD POST", "DELETE"));
    }

    #[test]
    fn within_expands_a_macro_operand() {
        let op = compile("@within %{tx.allowed_methods}");
        let ctx = vars(&[("tx.allowed_methods", "GET HEAD POST")]);
        assert!(op.evaluate(b"POST", &ctx, false).matched);
        assert!(!op.evaluate(b"TRACE", &ctx, false).matched);
    }

    #[test]
    fn numeric_operators_compare_and_accept_macros() {
        assert!(matches("@lt 5", "3"));
        assert!(!matches("@lt 5", "5"));
        assert!(matches("@ge 5", "5"));
        assert!(matches("@gt 5", "6"));
        assert!(matches("@eq 5", "5"));

        let op = compile("@ge %{tx.threshold}");
        let ctx = vars(&[("tx.threshold", "5")]);
        assert!(op.evaluate(b"7", &ctx, false).matched);
        assert!(!op.evaluate(b"4", &ctx, false).matched);
    }

    #[test]
    fn an_unset_numeric_macro_is_zero() {
        let op = compile("@ge %{tx.never_set}");
        assert!(op.evaluate(b"0", &EmptyContext, false).matched);
    }

    #[test]
    fn numeric_operators_read_a_leading_integer() {
        assert!(matches("@eq 0", ""));
        assert!(matches("@eq 12", "12abc"));
        assert!(matches("@eq 0", "abc"));
    }

    #[test]
    fn ip_match_handles_addresses_and_cidr() {
        assert!(matches("@ipMatch 192.168.1.1", "192.168.1.1"));
        assert!(!matches("@ipMatch 192.168.1.1", "192.168.1.2"));
        assert!(matches("@ipMatch 192.168.0.0/16", "192.168.99.4"));
        assert!(!matches("@ipMatch 192.168.0.0/16", "192.169.0.1"));
        assert!(matches("@ipMatch 10.0.0.0/8,192.168.0.0/16", "10.1.2.3"));
        assert!(matches("@ipMatch 2001:db8::/32", "2001:db8:1::1"));
        assert!(!matches("@ipMatch 2001:db8::/32", "2001:db9::1"));
    }

    #[test]
    fn ip_match_handles_odd_prefix_lengths() {
        assert!(matches("@ipMatch 10.0.0.0/9", "10.127.0.1"));
        assert!(!matches("@ipMatch 10.0.0.0/9", "10.128.0.1"));
    }

    #[test]
    fn ip_match_folds_v4_mapped_addresses() {
        assert!(matches("@ipMatch 192.168.0.0/16", "::ffff:192.168.1.1"));
    }

    #[test]
    fn ip_match_rejects_a_non_address_subject() {
        assert!(!matches("@ipMatch 10.0.0.0/8", "not-an-ip"));
    }

    #[test]
    fn ip_match_refuses_a_bad_operand_at_compile_time() {
        let op = Operator::parse("@ipMatch 999.1.1.1").unwrap();
        assert!(CompiledOperator::compile(&op, &NoDataLoader).is_err());
        let op = Operator::parse("@ipMatch 10.0.0.0/33").unwrap();
        assert!(CompiledOperator::compile(&op, &NoDataLoader).is_err());
    }

    #[test]
    fn validate_byte_range_matches_when_a_byte_is_outside() {
        // Rule 920270's shape: fires on a NUL byte.
        let op = compile("@validateByteRange 1-255");
        assert!(!op.evaluate(b"clean", &EmptyContext, false).matched);
        assert!(op.evaluate(b"has\0nul", &EmptyContext, false).matched);
        // Empty input never matches.
        assert!(!op.evaluate(b"", &EmptyContext, false).matched);
    }

    #[test]
    fn validate_utf8_encoding_matches_invalid_sequences() {
        let op = compile("@validateUtf8Encoding");
        assert!(
            !op.evaluate("caf\u{e9}".as_bytes(), &EmptyContext, false)
                .matched
        );
        assert!(op.evaluate(&[0xc3, 0x28], &EmptyContext, false).matched);
    }

    #[test]
    fn validate_url_encoding_matches_malformed_escapes() {
        let op = compile("@validateUrlEncoding");
        assert!(!op.evaluate(b"%41%42", &EmptyContext, false).matched);
        assert!(op.evaluate(b"%zz", &EmptyContext, false).matched);
        assert!(op.evaluate(b"%4", &EmptyContext, false).matched);
        assert!(op.evaluate(b"%", &EmptyContext, false).matched);
        assert!(!op.evaluate(b"", &EmptyContext, false).matched);
    }

    #[test]
    fn unconditional_match_always_matches() {
        assert!(matches("@unconditionalMatch", ""));
    }

    #[test]
    fn detect_sqli_classifies_with_libinjection() {
        assert!(matches("@detectSQLi", "1' OR '1'='1"));
        assert!(matches("@detectSQLi", "1 UNION SELECT password FROM users"));
        assert!(!matches("@detectSQLi", "hello world"));
    }

    #[test]
    fn detect_xss_classifies_with_libinjection() {
        assert!(matches("@detectXSS", "<script>alert(1)</script>"));
        assert!(matches("@detectXSS", "<img src=x onerror=alert(1)>"));
        assert!(!matches("@detectXSS", "hello world"));
    }

    #[test]
    fn detect_sqli_captures_the_fingerprint() {
        let m = compile("@detectSQLi").evaluate(b"1' OR '1'='1", &EmptyContext, true);
        assert!(m.matched);
        // The first capture is libinjection's fingerprint, a non-empty token.
        assert!(!m.captures.first().map(Vec::is_empty).unwrap_or(true));
    }

    #[test]
    fn pm_from_file_needs_a_loader() {
        let op = Operator::parse("@pmFromFile lfi-os-files.data").unwrap();
        let err = CompiledOperator::compile(&op, &NoDataLoader).unwrap_err();
        assert!(matches!(err, OperatorCompileError::DataFile(_)));
    }

    #[test]
    fn the_data_loader_refuses_to_escape_its_directory() {
        let loader = DirDataLoader::new("/tmp/parapet-test-data");
        assert!(loader.load("../../etc/passwd").is_err());
        assert!(loader.load("/etc/passwd").is_err());
    }

    #[test]
    fn dir_data_loader_reads_a_file_and_reports_a_missing_one() {
        let dir = std::env::temp_dir().join(format!("parapet-loader-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("phrases.data"), b"etc/passwd\nwin.ini\n").unwrap();
        let loader = DirDataLoader::new(&dir);
        assert_eq!(
            loader.load("phrases.data").unwrap(),
            b"etc/passwd\nwin.ini\n"
        );
        assert!(loader.load("absent.data").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pm_from_file_with_only_comments_fails_to_compile() {
        struct Empty;
        impl DataLoader for Empty {
            fn load(&self, _name: &str) -> Result<Vec<u8>, String> {
                Ok(b"# only a comment\n\n".to_vec())
            }
        }
        let op = Operator::parse("@pmFromFile x.data").unwrap();
        assert!(CompiledOperator::compile(&op, &Empty).is_err());
    }

    #[test]
    fn ip_match_folds_a_v4_mapped_network_against_a_v4_subject() {
        // A `::ffff:x.x.x.x` network compared against a bare v4 address.
        let op = compile("@ipMatch ::ffff:192.168.0.0/120");
        assert!(op.evaluate(b"192.168.0.5", &EmptyContext, false).matched);
        assert!(!op.evaluate(b"192.168.1.5", &EmptyContext, false).matched);
    }

    #[test]
    fn ip_match_reads_bracketed_v6_and_host_port_forms() {
        let v6 = compile("@ipMatch 2001:db8::/32");
        assert!(v6.evaluate(b"[2001:db8::1]", &EmptyContext, false).matched);
        let v4 = compile("@ipMatch 192.168.0.0/16");
        assert!(
            v4.evaluate(b"192.168.1.1:8080", &EmptyContext, false)
                .matched
        );
    }

    #[test]
    fn ip_match_rejects_non_utf8_and_unparseable_subjects() {
        let op = compile("@ipMatch 10.0.0.0/8");
        assert!(!op.evaluate(&[0xff, 0xfe], &EmptyContext, false).matched);
        assert!(!op.evaluate(b"", &EmptyContext, false).matched);
    }

    #[test]
    fn rx_capture_on_a_non_match_yields_no_groups() {
        let op = compile(r"@rx (\d+)-(\d+)");
        let r = op.evaluate(b"no digits here", &EmptyContext, true);
        assert!(!r.matched);
        assert!(r.captures.is_empty());
    }

    #[test]
    fn contains_and_within_handle_empty_and_oversized_operands() {
        // @within: subject inside operand; an empty subject is contained.
        assert!(matches("@within anything", ""));
        // @contains with a needle longer than the subject cannot match.
        assert!(!matches("@contains longerneedle", "hay"));
    }

    #[test]
    fn pm_from_file_skips_comments_and_blank_lines() {
        struct Inline;
        impl DataLoader for Inline {
            fn load(&self, _name: &str) -> Result<Vec<u8>, String> {
                Ok(b"# a comment\n\netc/passwd\n  win.ini  \n".to_vec())
            }
        }
        let op = Operator::parse("@pmFromFile files.data").unwrap();
        let compiled = CompiledOperator::compile(&op, &Inline).unwrap();
        assert!(
            compiled
                .evaluate(b"/../etc/passwd", &EmptyContext, false)
                .matched
        );
        assert!(
            compiled
                .evaluate(b"c:\\win.ini", &EmptyContext, false)
                .matched
        );
        // The comment must not become a pattern.
        assert!(
            !compiled
                .evaluate(b"a comment", &EmptyContext, false)
                .matched
        );
    }
}
