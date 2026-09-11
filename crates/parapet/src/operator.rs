//! SecLang operators.
//!
//! CRS v4.9.0 uses 18 of them. An operator outside that set fails parsing with
//! a named error rather than being treated as always-false, because an
//! operator nobody evaluates is a rule that cannot fire.

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// An operand that is either a literal number or a macro to expand at
/// evaluation time, such as `@lt %{tx.anomaly_score}`.
#[derive(Debug, Clone, PartialEq)]
pub enum Numeric {
    /// A literal, as written in the rule.
    Literal(i64),
    /// A `%{...}` reference, kept unexpanded.
    Macro(String),
}

impl Numeric {
    fn parse(arg: &str) -> Result<Self, String> {
        let arg = arg.trim();
        if arg.starts_with("%{") && arg.ends_with('}') {
            return Ok(Numeric::Macro(arg[2..arg.len() - 1].to_string()));
        }
        arg.parse::<i64>()
            .map(Numeric::Literal)
            .map_err(|_| format!("expected a number or %{{macro}}, found {arg:?}"))
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// A SecLang operator, with its operand.
#[derive(Debug, Clone, PartialEq)]
pub enum Operator {
    /// `@rx` regular expression. The pattern is kept as authored; compiling it
    /// is a separate step (see [`crate::regex_compat`]).
    Rx(String),
    /// `@pm` case-insensitive multi-pattern match over inline phrases.
    Pm(Vec<String>),
    /// `@pmFromFile` multi-pattern match over phrases loaded from a file.
    PmFromFile(String),
    /// `@streq` exact string equality.
    Streq(String),
    /// `@contains` substring.
    Contains(String),
    /// `@endsWith` suffix.
    EndsWith(String),
    /// `@within` the subject is one of the space-separated operand entries.
    Within(String),
    /// `@ipMatch` against a comma-separated list of addresses and CIDR ranges.
    IpMatch(String),
    /// `@lt` numeric less-than.
    Lt(Numeric),
    /// `@gt` numeric greater-than.
    Gt(Numeric),
    /// `@eq` numeric equality.
    Eq(Numeric),
    /// `@ge` numeric greater-or-equal.
    Ge(Numeric),
    /// `@detectSQLi` libinjection SQL injection classifier.
    DetectSqli,
    /// `@detectXSS` libinjection cross-site scripting classifier.
    DetectXss,
    /// `@validateUtf8Encoding` well-formed UTF-8.
    ValidateUtf8Encoding,
    /// `@validateUrlEncoding` well-formed percent-encoding.
    ValidateUrlEncoding,
    /// `@validateByteRange` every byte falls in one of the allowed ranges.
    ValidateByteRange(Vec<(u8, u8)>),
    /// `@unconditionalMatch` always true.
    UnconditionalMatch,
}

/// Why an operator could not be parsed.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum OperatorError {
    /// The operator name is not one Parapet implements.
    #[error("unsupported operator @{name}: Parapet implements the 18 operators the Core Rule Set uses, and refuses rather than silently never matching")]
    Unsupported {
        /// The operator name as written, without the `@`.
        name: String,
    },
    /// The operator name is known but its operand is malformed.
    #[error("operator @{name}: {detail}")]
    BadOperand {
        /// The operator name.
        name: String,
        /// What was wrong.
        detail: String,
    },
}

impl Operator {
    /// Parse an operator and its operand.
    ///
    /// `body` is the operator argument with any leading `!` already stripped
    /// by the caller. A body that does not start with `@` is an implicit
    /// `@rx`, which SecLang permits.
    pub fn parse(body: &str) -> Result<Self, OperatorError> {
        let body = body.trim_start();
        let Some(rest) = body.strip_prefix('@') else {
            return Ok(Operator::Rx(body.to_string()));
        };

        let (name, arg) = match rest.find(char::is_whitespace) {
            Some(i) => (&rest[..i], rest[i..].trim_start()),
            None => (rest, ""),
        };

        let bad = |detail: String| OperatorError::BadOperand {
            name: name.to_string(),
            detail,
        };
        let num = |arg: &str| Numeric::parse(arg).map_err(&bad);

        Ok(match name {
            "rx" => Operator::Rx(arg.to_string()),
            "pm" => {
                let phrases: Vec<String> = arg.split_whitespace().map(str::to_string).collect();
                if phrases.is_empty() {
                    return Err(bad("no phrases given".into()));
                }
                Operator::Pm(phrases)
            }
            "pmFromFile" | "pmf" => {
                if arg.is_empty() {
                    return Err(bad("no file given".into()));
                }
                Operator::PmFromFile(arg.to_string())
            }
            "streq" => Operator::Streq(arg.to_string()),
            "contains" => Operator::Contains(arg.to_string()),
            "endsWith" => Operator::EndsWith(arg.to_string()),
            "within" => Operator::Within(arg.to_string()),
            "ipMatch" => {
                if arg.is_empty() {
                    return Err(bad("no addresses given".into()));
                }
                Operator::IpMatch(arg.to_string())
            }
            "lt" => Operator::Lt(num(arg)?),
            "gt" => Operator::Gt(num(arg)?),
            "eq" => Operator::Eq(num(arg)?),
            "ge" => Operator::Ge(num(arg)?),
            "detectSQLi" => Operator::DetectSqli,
            "detectXSS" => Operator::DetectXss,
            "validateUtf8Encoding" => Operator::ValidateUtf8Encoding,
            "validateUrlEncoding" => Operator::ValidateUrlEncoding,
            "validateByteRange" => {
                Operator::ValidateByteRange(parse_byte_ranges(arg).map_err(bad)?)
            }
            "unconditionalMatch" => Operator::UnconditionalMatch,
            other => {
                return Err(OperatorError::Unsupported {
                    name: other.to_string(),
                })
            }
        })
    }

    /// The operator's name as written in SecLang, without the `@`.
    pub fn name(&self) -> &'static str {
        match self {
            Operator::Rx(_) => "rx",
            Operator::Pm(_) => "pm",
            Operator::PmFromFile(_) => "pmFromFile",
            Operator::Streq(_) => "streq",
            Operator::Contains(_) => "contains",
            Operator::EndsWith(_) => "endsWith",
            Operator::Within(_) => "within",
            Operator::IpMatch(_) => "ipMatch",
            Operator::Lt(_) => "lt",
            Operator::Gt(_) => "gt",
            Operator::Eq(_) => "eq",
            Operator::Ge(_) => "ge",
            Operator::DetectSqli => "detectSQLi",
            Operator::DetectXss => "detectXSS",
            Operator::ValidateUtf8Encoding => "validateUtf8Encoding",
            Operator::ValidateUrlEncoding => "validateUrlEncoding",
            Operator::ValidateByteRange(_) => "validateByteRange",
            Operator::UnconditionalMatch => "unconditionalMatch",
        }
    }
}

/// Parse `@validateByteRange` operands such as `9,10,13,32-126,128-255`.
fn parse_byte_ranges(arg: &str) -> Result<Vec<(u8, u8)>, String> {
    if arg.trim().is_empty() {
        return Err("no ranges given".into());
    }
    let mut ranges = Vec::new();
    for part in arg.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (lo, hi) = match part.split_once('-') {
            Some((lo, hi)) => (lo.trim(), hi.trim()),
            None => (part, part),
        };
        let lo: u8 = lo
            .parse()
            .map_err(|_| format!("{lo:?} is not a byte value"))?;
        let hi: u8 = hi
            .parse()
            .map_err(|_| format!("{hi:?} is not a byte value"))?;
        if lo > hi {
            return Err(format!("range {lo}-{hi} is inverted"));
        }
        ranges.push((lo, hi));
    }
    Ok(ranges)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn bare_operand_is_an_implicit_rx() {
        assert_eq!(
            Operator::parse("^\\d+$").unwrap(),
            Operator::Rx("^\\d+$".into())
        );
    }

    #[test]
    fn parses_the_operators_crs_uses() {
        assert_eq!(
            Operator::parse("@detectSQLi").unwrap(),
            Operator::DetectSqli
        );
        assert_eq!(Operator::parse("@detectXSS").unwrap(), Operator::DetectXss);
        assert_eq!(
            Operator::parse("@streq GET").unwrap(),
            Operator::Streq("GET".into())
        );
        assert_eq!(
            Operator::parse("@lt 5").unwrap(),
            Operator::Lt(Numeric::Literal(5))
        );
        assert_eq!(
            Operator::parse("@pmFromFile lfi-os-files.data").unwrap(),
            Operator::PmFromFile("lfi-os-files.data".into())
        );
    }

    #[test]
    fn numeric_operand_accepts_a_macro() {
        assert_eq!(
            Operator::parse("@ge %{tx.inbound_anomaly_score_threshold}").unwrap(),
            Operator::Ge(Numeric::Macro("tx.inbound_anomaly_score_threshold".into()))
        );
    }

    #[test]
    fn pm_splits_phrases_on_whitespace() {
        assert_eq!(
            Operator::parse("@pm alpha beta gamma").unwrap(),
            Operator::Pm(vec!["alpha".into(), "beta".into(), "gamma".into()])
        );
    }

    #[test]
    fn byte_ranges_parse_singles_and_spans() {
        let op = Operator::parse("@validateByteRange 9,10,13,32-126,128-255").unwrap();
        assert_eq!(
            op,
            Operator::ValidateByteRange(vec![(9, 9), (10, 10), (13, 13), (32, 126), (128, 255)])
        );
    }

    #[test]
    fn unsupported_operator_is_an_error_not_a_no_op() {
        let err = Operator::parse("@rbl example.com").unwrap_err();
        assert!(matches!(err, OperatorError::Unsupported { .. }));
        assert!(err.to_string().contains("silently never matching"));
    }

    #[test]
    fn malformed_numeric_operand_is_rejected() {
        let err = Operator::parse("@lt not-a-number").unwrap_err();
        assert!(matches!(err, OperatorError::BadOperand { .. }));
    }

    #[test]
    fn inverted_byte_range_is_rejected() {
        assert!(Operator::parse("@validateByteRange 90-65").is_err());
    }

    #[test]
    fn operators_needing_an_operand_reject_an_empty_one() {
        assert!(Operator::parse("@pm").is_err());
        assert!(Operator::parse("@pmFromFile").is_err());
        assert!(Operator::parse("@ipMatch").is_err());
        assert!(Operator::parse("@validateByteRange").is_err());
    }

    #[test]
    fn byte_ranges_skip_empty_parts() {
        assert_eq!(
            Operator::parse("@validateByteRange 9,,10").unwrap(),
            Operator::ValidateByteRange(vec![(9, 9), (10, 10)])
        );
        assert!(Operator::parse("@validateByteRange 9,notabyte").is_err());
    }

    #[test]
    fn parses_the_remaining_operators() {
        assert_eq!(
            Operator::parse("@contains x").unwrap(),
            Operator::Contains("x".into())
        );
        assert_eq!(
            Operator::parse("@endsWith .php").unwrap(),
            Operator::EndsWith(".php".into())
        );
        assert_eq!(
            Operator::parse("@within GET POST").unwrap(),
            Operator::Within("GET POST".into())
        );
        assert_eq!(
            Operator::parse("@ipMatch 10.0.0.0/8").unwrap(),
            Operator::IpMatch("10.0.0.0/8".into())
        );
        assert_eq!(
            Operator::parse("@gt 5").unwrap(),
            Operator::Gt(Numeric::Literal(5))
        );
        assert_eq!(
            Operator::parse("@eq 5").unwrap(),
            Operator::Eq(Numeric::Literal(5))
        );
        assert_eq!(
            Operator::parse("@validateUtf8Encoding").unwrap(),
            Operator::ValidateUtf8Encoding
        );
        assert_eq!(
            Operator::parse("@validateUrlEncoding").unwrap(),
            Operator::ValidateUrlEncoding
        );
        assert_eq!(
            Operator::parse("@unconditionalMatch").unwrap(),
            Operator::UnconditionalMatch
        );
    }

    #[test]
    fn every_operator_reports_its_name() {
        let ops = [
            Operator::Rx(String::new()),
            Operator::Pm(vec![]),
            Operator::PmFromFile(String::new()),
            Operator::Streq(String::new()),
            Operator::Contains(String::new()),
            Operator::EndsWith(String::new()),
            Operator::Within(String::new()),
            Operator::IpMatch(String::new()),
            Operator::Lt(Numeric::Literal(0)),
            Operator::Gt(Numeric::Literal(0)),
            Operator::Eq(Numeric::Literal(0)),
            Operator::Ge(Numeric::Literal(0)),
            Operator::DetectSqli,
            Operator::DetectXss,
            Operator::ValidateUtf8Encoding,
            Operator::ValidateUrlEncoding,
            Operator::ValidateByteRange(vec![]),
            Operator::UnconditionalMatch,
        ];
        let names: Vec<&str> = ops.iter().map(Operator::name).collect();
        assert_eq!(names.len(), 18);
        assert!(names.contains(&"rx"));
        assert!(names.contains(&"detectSQLi"));
        assert!(names.contains(&"unconditionalMatch"));
        // Every name is distinct.
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 18);
    }
}
