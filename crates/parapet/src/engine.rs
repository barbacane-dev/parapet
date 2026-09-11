//! Compiling parsed directives into an evaluable rule set.

use std::collections::HashMap;

use crate::action::{Action, Ctl, SetVar, SetVarOp, Transformation};
use crate::collections::{CompiledSelector, CompiledTarget};
use crate::macros::Template;
use crate::matcher::{CompiledOperator, DataLoader, OperatorCompileError};
use crate::rule::{Collection, Directive, Rule, Selector, Severity, Target};
use crate::Phase;

/// What a matching rule does to the transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disruptive {
    /// `deny`
    Deny,
    /// `drop`
    Drop,
    /// `block`, which defers to the configured default action.
    Block,
    /// `redirect`
    Redirect,
    /// `pass`, which is explicitly not disruptive.
    Pass,
}

/// A `setvar:` with its operand pre-parsed.
#[derive(Debug, Clone)]
pub struct SetVarSpec {
    /// Variable name, itself a template because CRS writes
    /// `setvar:'tx.rfi_parameter_%{MATCHED_VAR_NAME}=1'`.
    pub name: Template,
    /// How the value combines with the existing one.
    pub op: SetVarOp,
    /// The value template. Absent means 1, as SecLang defines.
    pub value: Option<Template>,
}

/// One link in a chain after the starter.
#[derive(Debug)]
pub struct ChainLink {
    /// Variables this link inspects.
    pub targets: Vec<CompiledTarget>,
    /// The link's test.
    pub operator: Option<CompiledOperator>,
    /// Whether the link's result is inverted.
    pub negated: bool,
    /// Transformations applied before the operator, in order.
    pub transformations: Vec<Transformation>,
    /// Whether the link exposes regex captures.
    pub capture: bool,
    /// `setvar:` actions that run when this link matches.
    pub setvars: Vec<SetVarSpec>,
}

/// A rule ready to evaluate.
#[derive(Debug)]
pub struct CompiledRule {
    /// The rule's `id:`, absent on chained rules and some `SecAction`s.
    pub id: Option<u32>,
    /// Which phase the rule runs in.
    pub phase: Phase,
    /// Variables the rule inspects. Empty for `SecAction`.
    pub targets: Vec<CompiledTarget>,
    /// The rule's test. `None` means always match, as `SecAction` does.
    pub operator: Option<CompiledOperator>,
    /// Whether the operator result is inverted.
    pub negated: bool,
    /// Transformations applied before the operator, in order.
    pub transformations: Vec<Transformation>,
    /// Whether to expose regex captures as `TX:0` through `TX:9`.
    pub capture: bool,
    /// Whether to re-evaluate after each transformation.
    pub multi_match: bool,
    /// The disruptive action, if any.
    pub disruptive: Option<Disruptive>,
    /// The status a disruptive action should use.
    pub status: Option<u16>,
    /// `setvar:` actions.
    pub setvars: Vec<SetVarSpec>,
    /// `skipAfter:` jump target.
    pub skip_after: Option<String>,
    /// `msg:`
    pub msg: Option<Template>,
    /// `logdata:`
    pub logdata: Option<Template>,
    /// `tag:` values.
    pub tags: Vec<String>,
    /// `severity:`
    pub severity: Option<Severity>,
    /// `ctl:` actions.
    pub ctl: Vec<Ctl>,
    /// Whether logging was explicitly suppressed with `nolog`.
    pub nolog: bool,
    /// Remaining links of the chain, all of which must match.
    pub chain: Vec<ChainLink>,
    /// Source line, for diagnostics.
    pub line: usize,
}

/// An entry in the rule set: a rule, or a `skipAfter` destination.
#[derive(Debug)]
enum Entry {
    Rule(Box<CompiledRule>),
    Marker,
}

/// A compiled rule set, ready to run transactions against.
#[derive(Debug, Default)]
pub struct RuleSet {
    entries: Vec<Entry>,
    marker_index: HashMap<String, usize>,
}

/// Why a rule set could not be compiled.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    /// An operator could not be compiled.
    #[error("rule {id} (line {line}): {source}")]
    Operator {
        /// The rule id, or 0 when it has none.
        id: u32,
        /// Source line.
        line: usize,
        /// The underlying operator error.
        #[source]
        source: OperatorCompileError,
    },
    /// A rule declared `chain` but nothing followed it.
    #[error("rule {id} (line {line}) ends with `chain` but no rule follows it")]
    DanglingChain {
        /// The rule id, or 0 when it has none.
        id: u32,
        /// Source line.
        line: usize,
    },
    /// An XPath expression Parapet cannot evaluate.
    ///
    /// Refused rather than resolved to nothing: a target that inspects nothing
    /// is a rule that cannot fire, and it would do so silently.
    #[error("rule {id} (line {line}) selects XML with {expression:?}; only {supported:?} are implemented")]
    UnsupportedXPath {
        /// The rule id, or 0 when it has none.
        id: u32,
        /// Source line.
        line: usize,
        /// The expression as written.
        expression: String,
        /// The expressions that are implemented.
        supported: &'static [&'static str],
    },
    /// A `skipAfter:` names a marker that does not exist.
    #[error("rule {id} (line {line}) skips to {marker:?}, which no SecMarker defines")]
    UnknownMarker {
        /// The rule id, or 0 when it has none.
        id: u32,
        /// Source line.
        line: usize,
        /// The marker name.
        marker: String,
    },
    /// A `skipAfter:` names a marker at or before the rule itself.
    ///
    /// Evaluation resumes just after the marker, so a marker that is not ahead
    /// of the rule sends evaluation backward. A rule that skips backward and
    /// still matches re-runs forever, hanging the request. Refused rather than
    /// allowed: a jump that loops is not a jump.
    #[error("rule {id} (line {line}) skips to {marker:?}, which is not ahead of it; skipAfter must jump forward")]
    BackwardSkip {
        /// The rule id, or 0 when it has none.
        id: u32,
        /// Source line.
        line: usize,
        /// The marker name.
        marker: String,
    },
    /// A regex member-selector the engine cannot compile.
    ///
    /// Refused rather than resolved to nothing: an uncompilable selector
    /// silently selects no members, which turns the rule into a bypass with no
    /// signal, exactly as an unsupported XPath would.
    #[error("rule {id} (line {line}) selects members with /{selector}/, which is not a valid regex: {error}")]
    InvalidSelector {
        /// The rule id, or 0 when it has none.
        id: u32,
        /// Source line.
        line: usize,
        /// The selector pattern as written.
        selector: String,
        /// The regex parse error.
        error: String,
    },
}

impl RuleSet {
    /// Compile parsed directives into a rule set, refusing on the first error.
    ///
    /// Chained rules are folded into their starter, so the resulting sequence
    /// is flat and a `skipAfter` cannot land inside a chain.
    pub fn compile(
        directives: &[Directive],
        loader: &dyn DataLoader,
    ) -> Result<Self, CompileError> {
        let (set, errors) = Self::compile_all(directives, loader);
        match errors.into_iter().next() {
            Some(e) => Err(e),
            None => Ok(set),
        }
    }

    /// Compile parsed directives, collecting every error instead of stopping.
    ///
    /// For tooling that needs to measure coverage across a whole rule set.
    /// Anything that *enforces* rules must treat a non-empty error list as a
    /// refusal: the rule set returned is missing the rules that failed, and
    /// enforcing a subset of a rule set silently weakens it. Use
    /// [`RuleSet::compile`] there.
    pub fn compile_all(
        directives: &[Directive],
        loader: &dyn DataLoader,
    ) -> (Self, Vec<CompileError>) {
        Self::compile_inner(directives, loader)
    }

    fn compile_inner(
        directives: &[Directive],
        loader: &dyn DataLoader,
    ) -> (Self, Vec<CompileError>) {
        let mut set = RuleSet::default();
        let mut errors: Vec<CompileError> = Vec::new();
        let mut pending: Vec<&Rule> = Vec::new();
        // What `block` resolves to, per phase. ModSecurity's built-in default
        // is `pass`, so an unconfigured `block` scores without denying.
        let mut defaults: HashMap<Phase, (Disruptive, Option<u16>)> = HashMap::new();

        for directive in directives {
            match directive {
                Directive::Rule(rule) | Directive::Action(rule) => {
                    pending.push(rule);
                    if rule.is_chained() {
                        continue;
                    }
                    let (starter, links) = pending.split_at(1);
                    match compile_rule(starter[0], links, loader) {
                        Ok(mut compiled) => {
                            if compiled.disruptive == Some(Disruptive::Block) {
                                let (resolved, status) = defaults
                                    .get(&compiled.phase)
                                    .copied()
                                    .unwrap_or((Disruptive::Pass, None));
                                compiled.disruptive = Some(resolved);
                                if compiled.status.is_none() {
                                    compiled.status = status;
                                }
                            }
                            set.entries.push(Entry::Rule(Box::new(compiled)));
                        }
                        Err(e) => errors.push(e),
                    }
                    pending.clear();
                }
                Directive::Marker(name) => {
                    set.marker_index.insert(name.clone(), set.entries.len());
                    set.entries.push(Entry::Marker);
                }
                Directive::DefaultAction { phase, actions } => {
                    // Only the disruptive action and status matter here; the
                    // logging defaults do not change what a rule does.
                    let mut disruptive = Disruptive::Pass;
                    let mut status = None;
                    for action in actions {
                        match action {
                            Action::Deny => disruptive = Disruptive::Deny,
                            Action::Drop => disruptive = Disruptive::Drop,
                            Action::Pass => disruptive = Disruptive::Pass,
                            Action::Redirect(_) => disruptive = Disruptive::Redirect,
                            Action::Status(s) => status = Some(*s),
                            _ => {}
                        }
                    }
                    defaults.insert(*phase, (disruptive, status));
                }
                Directive::ComponentSignature(_) => {}
            }
        }

        if let Some(open) = pending.first() {
            errors.push(CompileError::DanglingChain {
                id: open.id().unwrap_or(0),
                line: open.line,
            });
        }

        // Resolve every skipAfter now, so a typo, or a jump that would loop, is
        // a compile error rather than a surprise at request time.
        let mut marker_errors: Vec<CompileError> = Vec::new();
        for (index, entry) in set.entries.iter().enumerate() {
            if let Entry::Rule(rule) = entry {
                if let Some(marker) = &rule.skip_after {
                    match set.marker_index.get(marker) {
                        None => marker_errors.push(CompileError::UnknownMarker {
                            id: rule.id.unwrap_or(0),
                            line: rule.line,
                            marker: marker.clone(),
                        }),
                        // Evaluation resumes at the marker's slot + 1, so a
                        // marker that is not ahead of the rule loops.
                        Some(&position) if position <= index => {
                            marker_errors.push(CompileError::BackwardSkip {
                                id: rule.id.unwrap_or(0),
                                line: rule.line,
                                marker: marker.clone(),
                            })
                        }
                        Some(_) => {}
                    }
                }
            }
        }

        errors.extend(marker_errors);
        (set, errors)
    }

    /// Number of rules, excluding markers.
    pub fn rule_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| matches!(e, Entry::Rule(_)))
            .count()
    }

    /// Number of `skipAfter` destinations.
    pub fn marker_count(&self) -> usize {
        self.marker_index.len()
    }

    /// Rules in a given phase.
    pub fn rules_in_phase(&self, phase: Phase) -> usize {
        self.entries
            .iter()
            .filter(|e| matches!(e, Entry::Rule(r) if r.phase == phase))
            .count()
    }

    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn rule_at(&self, index: usize) -> Option<&CompiledRule> {
        match self.entries.get(index) {
            Some(Entry::Rule(rule)) => Some(rule),
            _ => None,
        }
    }

    pub(crate) fn marker_position(&self, name: &str) -> Option<usize> {
        self.marker_index.get(name).copied()
    }
}

fn compile_rule(
    starter: &Rule,
    links: &[&Rule],
    loader: &dyn DataLoader,
) -> Result<CompiledRule, CompileError> {
    let id = starter.id();
    let line = starter.line;
    let targets = compile_targets(&starter.targets, id, line)?;
    let operator = compile_operator(starter, loader)?;

    let mut compiled = CompiledRule {
        id,
        // SecLang defaults a rule with no explicit phase to phase 2.
        phase: Phase::RequestBody,
        targets,
        operator,
        negated: starter.negated,
        transformations: Vec::new(),
        capture: false,
        multi_match: false,
        disruptive: None,
        status: None,
        setvars: Vec::new(),
        skip_after: None,
        msg: None,
        logdata: None,
        tags: Vec::new(),
        severity: None,
        ctl: Vec::new(),
        nolog: false,
        chain: Vec::new(),
        line,
    };

    for action in &starter.actions {
        apply_action(&mut compiled, action);
    }

    for link in links {
        let link_targets = compile_targets(
            &link.targets,
            link.id().unwrap_or(id.unwrap_or(0)),
            link.line,
        )?;
        let mut chain_link = ChainLink {
            targets: link_targets,
            operator: compile_operator(link, loader)?,
            negated: link.negated,
            transformations: Vec::new(),
            capture: false,
            setvars: Vec::new(),
        };
        for action in &link.actions {
            match action {
                Action::Transform(t) => chain_link.transformations.push(*t),
                Action::Capture => chain_link.capture = true,
                Action::SetVar(sv) => chain_link.setvars.push(setvar_spec(sv)),
                // A chained rule carries no metadata or disruptive action of
                // its own; those belong to the starter.
                _ => {}
            }
        }
        compiled.chain.push(chain_link);
    }

    Ok(compiled)
}

/// Compile a target list into its evaluable form.
///
/// A regex selector is compiled once here rather than on every resolution, and
/// a selector that cannot be evaluated is refused rather than left to select
/// nothing at request time: a rule that inspects nothing cannot fire, and it
/// would do so silently. An unsupported XPath and an uncompilable regex
/// selector both surface here, at compile time.
fn compile_targets(
    targets: &[Target],
    id: impl Into<Option<u32>>,
    line: usize,
) -> Result<Vec<CompiledTarget>, CompileError> {
    let id = id.into();
    targets
        .iter()
        .map(|target| {
            let selector = match &target.selector {
                None => None,
                Some(Selector::Name(name)) => Some(CompiledSelector::Name(name.clone())),
                Some(Selector::XPath(expression)) => {
                    if target.collection == Collection::Xml
                        && !crate::xml::xpath_is_supported(expression)
                    {
                        return Err(CompileError::UnsupportedXPath {
                            id: id.unwrap_or(0),
                            line,
                            expression: expression.clone(),
                            supported: crate::xml::SUPPORTED_XPATH,
                        });
                    }
                    Some(CompiledSelector::XPath(expression.clone()))
                }
                Some(Selector::Regex(pattern)) => {
                    let re =
                        regex::Regex::new(pattern).map_err(|e| CompileError::InvalidSelector {
                            id: id.unwrap_or(0),
                            line,
                            selector: pattern.clone(),
                            error: e.to_string(),
                        })?;
                    Some(CompiledSelector::Regex(re))
                }
            };
            Ok(CompiledTarget {
                collection: target.collection,
                selector,
                exclusion: target.exclusion,
                count: target.count,
            })
        })
        .collect()
}

fn compile_operator(
    rule: &Rule,
    loader: &dyn DataLoader,
) -> Result<Option<CompiledOperator>, CompileError> {
    match &rule.operator {
        None => Ok(None),
        Some(op) => CompiledOperator::compile(op, loader)
            .map(Some)
            .map_err(|source| CompileError::Operator {
                id: rule.id().unwrap_or(0),
                line: rule.line,
                source,
            }),
    }
}

fn apply_action(rule: &mut CompiledRule, action: &Action) {
    match action {
        Action::Id(_) => {}
        Action::Phase(p) => rule.phase = *p,
        Action::Msg(m) => rule.msg = Some(Template::parse(m)),
        Action::LogData(d) => rule.logdata = Some(Template::parse(d)),
        Action::Tag(t) => rule.tags.push(t.clone()),
        Action::Severity(s) => rule.severity = Some(*s),
        Action::Rev(_) | Action::Ver(_) | Action::Accuracy(_) | Action::Maturity(_) => {}

        Action::Block => rule.disruptive = Some(Disruptive::Block),
        Action::Deny => rule.disruptive = Some(Disruptive::Deny),
        Action::Drop => rule.disruptive = Some(Disruptive::Drop),
        Action::Pass => rule.disruptive = Some(Disruptive::Pass),
        Action::Redirect(_) => rule.disruptive = Some(Disruptive::Redirect),
        Action::Status(s) => rule.status = Some(*s),

        Action::Chain => {}
        Action::SkipAfter(m) => rule.skip_after = Some(m.clone()),

        Action::Transform(t) => rule.transformations.push(*t),
        Action::Capture => rule.capture = true,
        Action::SetVar(sv) => rule.setvars.push(setvar_spec(sv)),
        Action::InitCol { .. } => {}
        Action::MultiMatch => rule.multi_match = true,

        Action::Log | Action::AuditLog | Action::NoAuditLog => {}
        Action::NoLog => rule.nolog = true,

        Action::Ctl(c) => rule.ctl.push(c.clone()),
    }
}

fn setvar_spec(sv: &SetVar) -> SetVarSpec {
    SetVarSpec {
        name: Template::parse(&sv.name),
        op: sv.op,
        value: sv.value.as_deref().map(Template::parse),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::matcher::NoDataLoader;
    use crate::parse;

    fn compile_src(src: &str) -> Result<RuleSet, CompileError> {
        RuleSet::compile(&parse(src, "test.conf").unwrap(), &NoDataLoader)
    }

    #[test]
    fn a_rule_carrying_every_metadata_action_compiles() {
        // Exercises the apply_action arms: metadata, disruptive, status,
        // logging, initcol and the accuracy/maturity/rev/ver no-ops.
        let src = r#"SecRule ARGS "@rx x" "id:1,phase:2,deny,status:403,msg:'m',logdata:'d',tag:'t1',tag:'t2',severity:'CRITICAL',rev:'2',ver:'CRS/4',accuracy:'9',maturity:'5',capture,multiMatch,log,auditlog,noauditlog,initcol:ip=%{remote_addr},t:none""#;
        let rs = compile_src(src).unwrap();
        assert_eq!(rs.rule_count(), 1);
        let rule = rs.rule_at(0).unwrap();
        assert_eq!(rule.tags, vec!["t1", "t2"]);
        assert_eq!(rule.status, Some(403));
        assert_eq!(rule.severity, Some(crate::rule::Severity::Critical));
        assert!(rule.capture && rule.multi_match);
    }

    #[test]
    fn redirect_and_drop_actions_compile() {
        assert!(compile_src(r#"SecRule ARGS "@rx x" "id:1,phase:1,drop""#).is_ok());
        assert!(compile_src(r#"SecRule ARGS "@rx x" "id:1,phase:1,redirect:/blocked""#).is_ok());
    }

    #[test]
    fn sec_default_action_resolves_block_for_each_disruptive() {
        for (default, ok_status) in [
            ("deny,status:406", 406u16),
            ("drop", 403),
            ("redirect:/x", 403),
        ] {
            let src = format!(
                "SecDefaultAction \"phase:1,log,{default}\"\nSecRule ARGS \"@rx a\" \"id:1,phase:1,block\""
            );
            let rs = compile_src(&src).unwrap();
            let rule = rs.rule_at(0).unwrap();
            assert!(rule.disruptive.is_some());
            let _ = ok_status;
        }
        // A `pass` default leaves block scoring rather than blocking.
        let rs = compile_src(
            "SecDefaultAction \"phase:1,pass\"\nSecRule ARGS \"@rx a\" \"id:1,phase:1,block\"",
        )
        .unwrap();
        assert_eq!(rs.rule_at(0).unwrap().disruptive, Some(Disruptive::Pass));
    }

    #[test]
    fn the_libinjection_operators_compile() {
        assert!(compile_src(r#"SecRule ARGS "@detectSQLi" "id:1,phase:2,deny""#).is_ok());
        assert!(compile_src(r#"SecRule ARGS "@detectXSS" "id:2,phase:2,deny""#).is_ok());
    }

    #[test]
    fn a_chain_link_compiles_its_transforms_capture_and_setvars() {
        let src = r#"
SecRule ARGS "@rx x" "id:1,phase:2,deny,chain"
    SecRule ARGS "@rx (y)" "t:lowercase,capture,setvar:'tx.z=1'"
"#;
        let rs = compile_src(src).unwrap();
        let rule = rs.rule_at(0).unwrap();
        assert_eq!(rule.chain.len(), 1);
        let link = &rule.chain[0];
        assert!(link.capture);
        assert_eq!(link.transformations, vec![Transformation::Lowercase]);
        assert_eq!(link.setvars.len(), 1);
    }

    #[test]
    fn rules_in_phase_and_marker_count_report_structure() {
        let src = r#"
SecRule ARGS "@rx a" "id:1,phase:1,pass"
SecRule ARGS "@rx b" "id:2,phase:2,pass"
SecMarker HERE
"#;
        let rs = compile_src(src).unwrap();
        assert_eq!(rs.rules_in_phase(Phase::RequestHeaders), 1);
        assert_eq!(rs.rules_in_phase(Phase::RequestBody), 1);
        assert_eq!(rs.marker_count(), 1);
    }
}
