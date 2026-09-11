//! SecLang actions and transformations.
//!
//! CRS v4.9.0 uses 23 actions, 20 transformations and 6 `ctl:` directives.
//! Anything outside those sets fails parsing. An ignored disruptive action
//! turns a blocking rule into a logging rule without saying so, which is the
//! failure mode this crate exists to avoid.

use crate::rule::Severity;
use crate::Phase;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// A single action from a rule's action list.
#[derive(Debug, Clone, PartialEq)]
#[allow(missing_docs)]
pub enum Action {
    // Metadata
    Id(u32),
    Phase(Phase),
    Msg(String),
    LogData(String),
    Tag(String),
    Severity(Severity),
    Rev(String),
    Ver(String),
    Accuracy(u8),
    Maturity(u8),

    // Disruptive
    /// `block`, deferring to the configured default action.
    Block,
    Deny,
    Pass,
    Drop,
    Redirect(String),
    /// `status:403`, the status a disruptive action should use.
    Status(u16),

    // Flow
    Chain,
    SkipAfter(String),

    // Data
    /// `t:lowercase` and friends. Order within the action list is significant.
    Transform(Transformation),
    /// `capture`, exposing regex captures as `TX:0` through `TX:9`.
    Capture,
    /// `setvar:'tx.score=+%{tx.critical_anomaly_score}'`
    SetVar(SetVar),
    /// `initcol:ip=%{remote_addr}`
    InitCol {
        collection: String,
        value: String,
    },
    /// `multiMatch`, re-evaluating after each transformation.
    MultiMatch,

    // Logging
    Log,
    NoLog,
    AuditLog,
    NoAuditLog,

    // Engine control
    Ctl(Ctl),
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// A `setvar:` assignment.
#[derive(Debug, Clone, PartialEq)]
pub struct SetVar {
    /// The variable being written, such as `tx.sql_injection_score`. May
    /// contain `%{...}` macros, which are expanded at evaluation time.
    pub name: String,
    /// How the value is applied.
    pub op: SetVarOp,
    /// The value, unexpanded. `None` for a bare `setvar:tx.foo`, which sets 1.
    pub value: Option<String>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// How a `setvar:` combines with the existing value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetVarOp {
    /// `=`
    Set,
    /// `=+`
    Add,
    /// `=-`
    Subtract,
    /// A leading `!`, which deletes the variable.
    Delete,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// The `ctl:` directives CRS uses.
#[derive(Debug, Clone, PartialEq)]
#[allow(missing_docs)]
pub enum Ctl {
    /// `ctl:ruleEngine=On|Off|DetectionOnly`
    RuleEngine(RuleEngineMode),
    AuditEngine(String),
    ForceRequestBodyVariable(bool),
    RequestBodyProcessor(String),
    RuleRemoveById(String),
    RuleRemoveByTag(String),
    RuleRemoveTargetById {
        rule: String,
        target: String,
    },
    RuleRemoveTargetByTag {
        tag: String,
        target: String,
    },
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// What `ctl:ruleEngine` switches the engine to for the rest of the
/// transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum RuleEngineMode {
    On,
    Off,
    DetectionOnly,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// The transformations CRS applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Transformation {
    None,
    Base64Decode,
    CmdLine,
    CompressWhitespace,
    CssDecode,
    EscapeSeqDecode,
    HexEncode,
    HtmlEntityDecode,
    JsDecode,
    Length,
    Lowercase,
    NormalizePath,
    NormalizePathWin,
    RemoveCommentsChar,
    RemoveNulls,
    RemoveWhitespace,
    ReplaceComments,
    Sha1,
    UrlDecodeUni,
    Utf8ToUnicode,
}

impl Transformation {
    /// Parse a transformation name, case-insensitively.
    ///
    /// `normalisePath` is accepted as a spelling of `normalizePath`; CRS uses
    /// both.
    pub fn parse(name: &str) -> Option<Self> {
        use Transformation::*;
        Some(match name.to_ascii_lowercase().as_str() {
            "none" => None,
            "base64decode" => Base64Decode,
            "cmdline" => CmdLine,
            "compresswhitespace" => CompressWhitespace,
            "cssdecode" => CssDecode,
            "escapeseqdecode" => EscapeSeqDecode,
            "hexencode" => HexEncode,
            "htmlentitydecode" => HtmlEntityDecode,
            "jsdecode" => JsDecode,
            "length" => Length,
            "lowercase" => Lowercase,
            "normalizepath" | "normalisepath" => NormalizePath,
            "normalizepathwin" | "normalisepathwin" => NormalizePathWin,
            "removecommentschar" => RemoveCommentsChar,
            "removenulls" => RemoveNulls,
            "removewhitespace" => RemoveWhitespace,
            "replacecomments" => ReplaceComments,
            "sha1" => Sha1,
            "urldecodeuni" => UrlDecodeUni,
            "utf8tounicode" => Utf8ToUnicode,
            _ => return Option::None,
        })
    }
}

/// Why an action could not be parsed.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ActionError {
    /// The action name is not one Parapet implements.
    #[error("unsupported action {name:?}: Parapet implements the actions the Core Rule Set uses, and refuses rather than silently dropping one")]
    Unsupported {
        /// The action name as written.
        name: String,
    },
    /// The action is known but its argument is missing or malformed.
    #[error("action {name}: {detail}")]
    BadArgument {
        /// The action name.
        name: String,
        /// What was wrong.
        detail: String,
    },
}

impl Action {
    /// Parse one action, such as `id:942100`, `t:lowercase` or `nolog`.
    pub fn parse(text: &str) -> Result<Self, ActionError> {
        let text = text.trim();
        let (name, arg) = match text.split_once(':') {
            Some((n, a)) => (n.trim(), Some(unquote(a.trim()))),
            None => (text, Option::None),
        };

        let bad = |detail: String| ActionError::BadArgument {
            name: name.to_string(),
            detail,
        };
        let required = |arg: Option<String>| -> Result<String, ActionError> {
            arg.ok_or_else(|| bad("requires an argument".into()))
        };

        Ok(match name {
            "id" => {
                let raw = required(arg)?;
                Action::Id(
                    raw.parse()
                        .map_err(|_| bad(format!("{raw:?} is not a rule id")))?,
                )
            }
            "phase" => {
                let raw = required(arg)?;
                Action::Phase(
                    parse_phase(&raw).ok_or_else(|| bad(format!("unknown phase {raw:?}")))?,
                )
            }
            "msg" => Action::Msg(required(arg)?),
            "logdata" => Action::LogData(required(arg)?),
            "tag" => Action::Tag(required(arg)?),
            "severity" => {
                let raw = required(arg)?;
                Action::Severity(
                    Severity::parse(&raw)
                        .ok_or_else(|| bad(format!("unknown severity {raw:?}")))?,
                )
            }
            "rev" => Action::Rev(required(arg)?),
            "ver" => Action::Ver(required(arg)?),
            "accuracy" => Action::Accuracy(parse_small(&required(arg)?, name)?),
            "maturity" => Action::Maturity(parse_small(&required(arg)?, name)?),

            "block" => Action::Block,
            "deny" => Action::Deny,
            "pass" => Action::Pass,
            "drop" => Action::Drop,
            "redirect" => Action::Redirect(required(arg)?),
            "status" => {
                let raw = required(arg)?;
                Action::Status(
                    raw.parse()
                        .map_err(|_| bad(format!("{raw:?} is not an HTTP status")))?,
                )
            }

            "chain" => Action::Chain,
            "skipAfter" => Action::SkipAfter(required(arg)?),

            "t" => {
                let raw = required(arg)?;
                Action::Transform(
                    Transformation::parse(&raw)
                        .ok_or_else(|| bad(format!("unknown transformation {raw:?}")))?,
                )
            }
            "capture" => Action::Capture,
            "setvar" => Action::SetVar(parse_setvar(&required(arg)?).map_err(bad)?),
            "initcol" => {
                let raw = required(arg)?;
                let (collection, value) = raw
                    .split_once('=')
                    .ok_or_else(|| bad("expected collection=value".into()))?;
                Action::InitCol {
                    collection: collection.to_string(),
                    value: value.to_string(),
                }
            }
            "multiMatch" => Action::MultiMatch,

            "log" => Action::Log,
            "nolog" => Action::NoLog,
            "auditlog" => Action::AuditLog,
            "noauditlog" => Action::NoAuditLog,

            "ctl" => Action::Ctl(parse_ctl(&required(arg)?).map_err(bad)?),

            other => {
                return Err(ActionError::Unsupported {
                    name: other.to_string(),
                })
            }
        })
    }
}

fn parse_small(raw: &str, name: &str) -> Result<u8, ActionError> {
    raw.parse().map_err(|_| ActionError::BadArgument {
        name: name.to_string(),
        detail: format!("{raw:?} is not a value between 0 and 255"),
    })
}

fn parse_phase(raw: &str) -> Option<Phase> {
    Some(match raw.to_ascii_lowercase().as_str() {
        "1" | "request" => Phase::RequestHeaders,
        "2" => Phase::RequestBody,
        "3" | "response" => Phase::ResponseHeaders,
        "4" => Phase::ResponseBody,
        "5" | "logging" => Phase::Logging,
        _ => return None,
    })
}

/// Strip one layer of matching single or double quotes.
fn unquote(s: &str) -> String {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
            return s[1..s.len() - 1].to_string();
        }
    }
    s.to_string()
}

fn parse_setvar(arg: &str) -> Result<SetVar, String> {
    if let Some(name) = arg.strip_prefix('!') {
        return Ok(SetVar {
            name: name.to_string(),
            op: SetVarOp::Delete,
            value: None,
        });
    }
    let Some((name, value)) = arg.split_once('=') else {
        // `setvar:tx.foo` sets the variable to 1.
        return Ok(SetVar {
            name: arg.to_string(),
            op: SetVarOp::Set,
            value: None,
        });
    };
    let (op, value) = match value.strip_prefix('+') {
        Some(v) => (SetVarOp::Add, v),
        None => match value.strip_prefix('-') {
            Some(v) => (SetVarOp::Subtract, v),
            None => (SetVarOp::Set, value),
        },
    };
    if name.is_empty() {
        return Err("no variable name".into());
    }
    Ok(SetVar {
        name: name.to_string(),
        op,
        value: Some(value.to_string()),
    })
}

fn parse_ctl(arg: &str) -> Result<Ctl, String> {
    let (name, value) = arg
        .split_once('=')
        .ok_or_else(|| format!("expected name=value, found {arg:?}"))?;
    // Target-scoped forms are `ruleRemoveTargetById=RULE;TARGET`.
    let split_target = |value: &str| -> Result<(String, String), String> {
        value
            .split_once(';')
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .ok_or_else(|| format!("{name} expects RULE;TARGET, found {value:?}"))
    };
    Ok(match name {
        "ruleEngine" => Ctl::RuleEngine(match value.to_ascii_lowercase().as_str() {
            "on" => RuleEngineMode::On,
            "off" => RuleEngineMode::Off,
            "detectiononly" => RuleEngineMode::DetectionOnly,
            other => return Err(format!("unknown ruleEngine value {other:?}")),
        }),
        "auditEngine" => Ctl::AuditEngine(value.to_string()),
        "forceRequestBodyVariable" => {
            Ctl::ForceRequestBodyVariable(value.eq_ignore_ascii_case("on"))
        }
        "requestBodyProcessor" => Ctl::RequestBodyProcessor(value.to_string()),
        "ruleRemoveById" => Ctl::RuleRemoveById(value.to_string()),
        "ruleRemoveByTag" => Ctl::RuleRemoveByTag(value.to_string()),
        "ruleRemoveTargetById" => {
            let (rule, target) = split_target(value)?;
            Ctl::RuleRemoveTargetById { rule, target }
        }
        "ruleRemoveTargetByTag" => {
            let (tag, target) = split_target(value)?;
            Ctl::RuleRemoveTargetByTag { tag, target }
        }
        other => return Err(format!("unsupported ctl directive {other:?}")),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_metadata_actions() {
        assert_eq!(Action::parse("id:942100").unwrap(), Action::Id(942100));
        assert_eq!(
            Action::parse("phase:2").unwrap(),
            Action::Phase(Phase::RequestBody)
        );
        assert_eq!(
            Action::parse("severity:'CRITICAL'").unwrap(),
            Action::Severity(Severity::Critical)
        );
    }

    #[test]
    fn parses_flag_actions() {
        assert_eq!(Action::parse("nolog").unwrap(), Action::NoLog);
        assert_eq!(Action::parse("capture").unwrap(), Action::Capture);
        assert_eq!(Action::parse("chain").unwrap(), Action::Chain);
        assert_eq!(Action::parse("multiMatch").unwrap(), Action::MultiMatch);
    }

    #[test]
    fn quotes_are_stripped_from_arguments() {
        assert_eq!(
            Action::parse("msg:'SQL Injection Attack'").unwrap(),
            Action::Msg("SQL Injection Attack".into())
        );
    }

    #[test]
    fn setvar_handles_all_four_forms() {
        assert_eq!(
            Action::parse("setvar:'tx.score=+%{tx.critical_anomaly_score}'").unwrap(),
            Action::SetVar(SetVar {
                name: "tx.score".into(),
                op: SetVarOp::Add,
                value: Some("%{tx.critical_anomaly_score}".into()),
            })
        );
        assert_eq!(
            Action::parse("setvar:'tx.foo=1'").unwrap(),
            Action::SetVar(SetVar {
                name: "tx.foo".into(),
                op: SetVarOp::Set,
                value: Some("1".into()),
            })
        );
        assert_eq!(
            Action::parse("setvar:!tx.foo").unwrap(),
            Action::SetVar(SetVar {
                name: "tx.foo".into(),
                op: SetVarOp::Delete,
                value: None,
            })
        );
        assert_eq!(
            Action::parse("setvar:tx.bare").unwrap(),
            Action::SetVar(SetVar {
                name: "tx.bare".into(),
                op: SetVarOp::Set,
                value: None,
            })
        );
    }

    #[test]
    fn transformation_accepts_the_british_spelling() {
        assert_eq!(
            Transformation::parse("normalisePath"),
            Some(Transformation::NormalizePath)
        );
        assert_eq!(
            Transformation::parse("normalizePath"),
            Some(Transformation::NormalizePath)
        );
    }

    #[test]
    fn ctl_target_forms_parse() {
        assert_eq!(
            Action::parse("ctl:ruleRemoveTargetById=942100;ARGS:foo").unwrap(),
            Action::Ctl(Ctl::RuleRemoveTargetById {
                rule: "942100".into(),
                target: "ARGS:foo".into()
            })
        );
    }

    #[test]
    fn unsupported_action_is_an_error_not_a_no_op() {
        let err = Action::parse("exec:/bin/sh").unwrap_err();
        assert!(matches!(err, ActionError::Unsupported { .. }));
        assert!(err.to_string().contains("silently dropping"));
    }

    #[test]
    fn unknown_transformation_is_rejected() {
        let err = Action::parse("t:rot13").unwrap_err();
        assert!(matches!(err, ActionError::BadArgument { .. }));
    }

    #[test]
    fn missing_required_argument_is_rejected() {
        assert!(Action::parse("id").is_err());
        assert!(Action::parse("msg").is_err());
    }

    #[test]
    fn parses_every_phase_spelling() {
        for (spec, phase) in [
            ("phase:1", Phase::RequestHeaders),
            ("phase:request", Phase::RequestHeaders),
            ("phase:2", Phase::RequestBody),
            ("phase:3", Phase::ResponseHeaders),
            ("phase:response", Phase::ResponseHeaders),
            ("phase:4", Phase::ResponseBody),
            ("phase:5", Phase::Logging),
            ("phase:logging", Phase::Logging),
        ] {
            assert_eq!(Action::parse(spec).unwrap(), Action::Phase(phase));
        }
        assert!(Action::parse("phase:9").is_err());
    }

    #[test]
    fn parses_accuracy_and_maturity_and_rejects_bad_values() {
        assert_eq!(Action::parse("accuracy:9").unwrap(), Action::Accuracy(9));
        assert_eq!(Action::parse("maturity:5").unwrap(), Action::Maturity(5));
        assert!(Action::parse("accuracy:xyz").is_err());
        assert!(Action::parse("maturity:999").is_err());
    }

    #[test]
    fn parses_disruptive_and_metadata_actions() {
        assert_eq!(Action::parse("deny").unwrap(), Action::Deny);
        assert_eq!(Action::parse("drop").unwrap(), Action::Drop);
        assert_eq!(Action::parse("pass").unwrap(), Action::Pass);
        assert_eq!(Action::parse("block").unwrap(), Action::Block);
        assert_eq!(
            Action::parse("redirect:/blocked").unwrap(),
            Action::Redirect("/blocked".into())
        );
        assert_eq!(Action::parse("status:406").unwrap(), Action::Status(406));
        assert!(Action::parse("status:notnum").is_err());
        assert_eq!(Action::parse("rev:2").unwrap(), Action::Rev("2".into()));
        assert_eq!(
            Action::parse("ver:OWASP_CRS/4.0").unwrap(),
            Action::Ver("OWASP_CRS/4.0".into())
        );
        assert_eq!(
            Action::parse("tag:attack-sqli").unwrap(),
            Action::Tag("attack-sqli".into())
        );
        assert_eq!(
            Action::parse("logdata:x").unwrap(),
            Action::LogData("x".into())
        );
        assert_eq!(Action::parse("log").unwrap(), Action::Log);
        assert_eq!(Action::parse("auditlog").unwrap(), Action::AuditLog);
        assert_eq!(Action::parse("noauditlog").unwrap(), Action::NoAuditLog);
        assert_eq!(
            Action::parse("skipAfter:END").unwrap(),
            Action::SkipAfter("END".into())
        );
    }

    #[test]
    fn parses_initcol_and_rejects_a_missing_equals() {
        assert_eq!(
            Action::parse("initcol:ip=%{remote_addr}").unwrap(),
            Action::InitCol {
                collection: "ip".into(),
                value: "%{remote_addr}".into()
            }
        );
        assert!(Action::parse("initcol:noequals").is_err());
    }

    #[test]
    fn setvar_without_a_name_is_rejected() {
        assert!(Action::parse("setvar:=5").is_err());
    }

    #[test]
    fn parses_every_ctl_directive() {
        use RuleEngineMode::*;
        for (spec, mode) in [
            ("ctl:ruleEngine=On", On),
            ("ctl:ruleEngine=Off", Off),
            ("ctl:ruleEngine=DetectionOnly", DetectionOnly),
        ] {
            assert_eq!(
                Action::parse(spec).unwrap(),
                Action::Ctl(Ctl::RuleEngine(mode))
            );
        }
        assert_eq!(
            Action::parse("ctl:auditEngine=Off").unwrap(),
            Action::Ctl(Ctl::AuditEngine("Off".into()))
        );
        assert_eq!(
            Action::parse("ctl:forceRequestBodyVariable=On").unwrap(),
            Action::Ctl(Ctl::ForceRequestBodyVariable(true))
        );
        assert_eq!(
            Action::parse("ctl:requestBodyProcessor=XML").unwrap(),
            Action::Ctl(Ctl::RequestBodyProcessor("XML".into()))
        );
        assert_eq!(
            Action::parse("ctl:ruleRemoveById=942100").unwrap(),
            Action::Ctl(Ctl::RuleRemoveById("942100".into()))
        );
        assert_eq!(
            Action::parse("ctl:ruleRemoveByTag=attack-sqli").unwrap(),
            Action::Ctl(Ctl::RuleRemoveByTag("attack-sqli".into()))
        );
        assert_eq!(
            Action::parse("ctl:ruleRemoveTargetByTag=tag;ARGS:x").unwrap(),
            Action::Ctl(Ctl::RuleRemoveTargetByTag {
                tag: "tag".into(),
                target: "ARGS:x".into()
            })
        );
    }

    #[test]
    fn malformed_ctl_directives_are_rejected() {
        assert!(Action::parse("ctl:noequals").is_err());
        assert!(Action::parse("ctl:ruleEngine=Sideways").is_err());
        assert!(Action::parse("ctl:bogusDirective=1").is_err());
        assert!(Action::parse("ctl:ruleRemoveTargetById=942100").is_err());
    }
}
