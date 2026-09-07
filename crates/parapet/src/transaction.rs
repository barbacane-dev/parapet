//! Running a request through a rule set.
//!
//! A transaction is fed the request in the order a proxy learns it, and each
//! `process_*` call runs the rules for that phase. Evaluation stops at the
//! first disruptive action, as SecLang specifies.

use crate::action::{Ctl, RuleEngineMode, SetVarOp, Transformation};
use crate::collections::{BodyError, Value, Variables};
use crate::engine::{ChainLink, CompiledRule, Disruptive, RuleSet, SetVarSpec};
use crate::matcher::CompiledOperator;
use crate::rule::Target;
use crate::{Phase, Verdict};

/// Whether the engine blocks or only records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EngineMode {
    /// Disruptive actions take effect.
    #[default]
    Blocking,
    /// Rules are evaluated and logged, but nothing is interrupted. Useful for
    /// tuning, and not a security control.
    DetectionOnly,
}

/// One rule that matched.
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// Whether the rule would appear in the audit log. A `nolog` rule still
    /// matched and still scored; it just does not log.
    pub logged: bool,
    /// The rule's id.
    pub id: Option<u32>,
    /// The expanded `msg:`.
    pub message: String,
    /// The expanded `logdata:`.
    pub data: String,
    /// The rule's tags.
    pub tags: Vec<String>,
    /// The name of the variable that matched, as `MATCHED_VAR_NAME` reports.
    pub matched_name: String,
}

/// An in-flight transaction.
pub struct Transaction<'r> {
    rules: &'r RuleSet,
    mode: EngineMode,
    /// Transaction variables, public so an embedder can seed `TX` the way
    /// `crs-setup.conf` does.
    pub vars: Variables,
    verdict: Verdict,
    matches: Vec<RuleMatch>,
    body_error: Option<BodyError>,
    completed: Option<Phase>,
    /// Rules switched off for this transaction by `ctl:ruleRemoveById`.
    removed_ids: std::collections::HashSet<u32>,
    /// Rules switched off by `ctl:ruleRemoveByTag`.
    removed_tags: std::collections::HashSet<String>,
    /// Targets removed from specific rules by `ctl:ruleRemoveTargetById`.
    removed_targets: Vec<(RuleSelector, String)>,
    /// Set by `ctl:ruleEngine=Off`, which stops further evaluation.
    engine_off: bool,
}

/// One operator evaluation: what to inspect, how to prepare it, and what to
/// test it with.
struct Step<'a> {
    targets: &'a [Target],
    operator: &'a CompiledOperator,
    negated: bool,
    transformations: &'a [Transformation],
    capture: bool,
    multi_match: bool,
    /// Targets removed by `ctl:ruleRemoveTarget*`.
    excluded: &'a [String],
}

/// How a `ctl:ruleRemoveTarget*` names the rules it applies to.
#[derive(Debug, Clone)]
enum RuleSelector {
    Id(String),
    Tag(String),
}

impl<'r> Transaction<'r> {
    /// Start a transaction against a rule set.
    pub fn new(rules: &'r RuleSet, mode: EngineMode) -> Self {
        Transaction {
            rules,
            mode,
            vars: Variables::default(),
            verdict: Verdict::Allow,
            matches: Vec::new(),
            body_error: None,
            completed: None,
            removed_ids: Default::default(),
            removed_tags: Default::default(),
            removed_targets: Vec::new(),
            engine_off: false,
        }
    }

    /// Seed a `TX` variable, as `crs-setup.conf` does with paranoia levels and
    /// anomaly thresholds.
    ///
    /// This matters more than it looks: CRS gates whole rule files on
    /// `TX:DETECTION_PARANOIA_LEVEL`, and an unset variable reads as 0, which
    /// would skip them all.
    pub fn set_tx(&mut self, name: &str, value: impl Into<Vec<u8>>) {
        self.vars.tx_set(name, value.into());
    }

    /// Record the connection's remote address.
    pub fn set_remote_addr(&mut self, addr: impl Into<Vec<u8>>) {
        self.vars.remote_addr = addr.into();
    }

    /// Record the request line and derive the URI variables from it.
    pub fn process_uri(&mut self, method: &str, uri: &str, protocol: &str) {
        self.vars.request_method = method.as_bytes().to_vec();
        self.vars.request_uri = uri.as_bytes().to_vec();
        self.vars.request_uri_raw = uri.as_bytes().to_vec();
        self.vars.request_protocol = protocol.as_bytes().to_vec();
        self.vars.request_line = format!("{method} {uri} {protocol}").into_bytes();

        let (path, query) = match uri.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (uri, None),
        };
        self.vars.request_filename = path.as_bytes().to_vec();
        self.vars.request_basename = path.rsplit('/').next().unwrap_or(path).as_bytes().to_vec();
        if let Some(query) = query {
            self.vars.query_string = query.as_bytes().to_vec();
            for (name, value) in parse_urlencoded(query.as_bytes()) {
                self.vars.args_get.push(name, value);
            }
        }
    }

    /// Add a request header. Call before [`Self::process_request_headers`].
    pub fn add_request_header(&mut self, name: &str, value: &str) {
        if name.eq_ignore_ascii_case("cookie") {
            for (cookie, cvalue) in parse_cookies(value.as_bytes()) {
                self.vars.request_cookies.push(cookie, cvalue);
            }
        }
        self.vars.request_headers.push(name, value.as_bytes());
    }

    /// Run phase 1.
    pub fn process_request_headers(&mut self) -> Verdict {
        self.run_phase(Phase::RequestHeaders)
    }

    /// Supply the request body and parse it according to `content_type`.
    ///
    /// A body in a format with no parser sets a body error, which SecLang
    /// exposes as `REQBODY_ERROR`. That is deliberate: an XML payload must be
    /// refused rather than inspected against an empty collection.
    pub fn set_request_body(&mut self, body: &[u8], content_type: Option<&str>) {
        self.vars.request_body = body.to_vec();
        let ct = content_type.unwrap_or("").to_ascii_lowercase();
        let base = ct.split(';').next().unwrap_or("").trim();
        match base {
            "application/x-www-form-urlencoded" => {
                self.vars.reqbody_processor = b"URLENCODED".to_vec();
                for (name, value) in parse_urlencoded(body) {
                    self.vars.args_post.push(name, value);
                }
            }
            "multipart/form-data" => {
                self.vars.reqbody_processor = b"MULTIPART".to_vec();
                self.body_error = Some(BodyError::UnsupportedFormat(
                    "multipart bodies are not parsed yet",
                ));
            }
            "text/xml" | "application/xml" | "application/soap+xml" => {
                self.vars.reqbody_processor = b"XML".to_vec();
                self.body_error = Some(BodyError::UnsupportedFormat(
                    "XML bodies are not parsed yet",
                ));
            }
            "application/json" => {
                self.vars.reqbody_processor = b"JSON".to_vec();
                self.body_error = Some(BodyError::UnsupportedFormat(
                    "JSON bodies are not parsed yet",
                ));
            }
            _ => {}
        }
        if self.body_error.is_some() {
            self.vars.tx_set("reqbody_error", b"1".to_vec());
        }
    }

    /// Whether a body could not be parsed, and why.
    pub fn body_error(&self) -> Option<&BodyError> {
        self.body_error.as_ref()
    }

    /// Run phase 2.
    pub fn process_request_body(&mut self) -> Verdict {
        self.run_phase(Phase::RequestBody)
    }

    /// Record the response status.
    pub fn set_response_status(&mut self, status: u16) {
        self.vars.response_status = status.to_string().into_bytes();
    }

    /// Add a response header.
    pub fn add_response_header(&mut self, name: &str, value: &str) {
        self.vars.response_headers.push(name, value.as_bytes());
    }

    /// Run phase 3.
    pub fn process_response_headers(&mut self) -> Verdict {
        self.run_phase(Phase::ResponseHeaders)
    }

    /// Supply the response body.
    pub fn set_response_body(&mut self, body: &[u8]) {
        self.vars.response_body = body.to_vec();
    }

    /// Run phase 4.
    pub fn process_response_body(&mut self) -> Verdict {
        self.run_phase(Phase::ResponseBody)
    }

    /// Run phase 5.
    pub fn process_logging(&mut self) -> Verdict {
        self.run_phase(Phase::Logging)
    }

    /// The verdict so far.
    pub fn verdict(&self) -> &Verdict {
        &self.verdict
    }

    /// Every rule that matched, in order.
    pub fn matches(&self) -> &[RuleMatch] {
        &self.matches
    }

    /// The ids of every rule that matched.
    pub fn matched_ids(&self) -> Vec<u32> {
        self.matches.iter().filter_map(|m| m.id).collect()
    }

    /// The last phase that ran to completion.
    pub fn last_completed_phase(&self) -> Option<Phase> {
        self.completed
    }

    /// Read an anomaly score out of `TX`.
    pub fn anomaly_score(&self, name: &str) -> i64 {
        self.vars.tx_number(name)
    }

    fn run_phase(&mut self, phase: Phase) -> Verdict {
        // A disruptive action already fired; later phases do not run.
        if self.verdict != Verdict::Allow {
            return self.verdict.clone();
        }

        let mut index = 0usize;
        while index < self.rules.entry_count() {
            let Some(rule) = self.rules.rule_at(index) else {
                index += 1;
                continue;
            };
            if rule.phase != phase {
                index += 1;
                continue;
            }
            if self.engine_off || self.is_removed(rule) {
                index += 1;
                continue;
            }

            if !self.evaluate(rule) {
                index += 1;
                continue;
            }

            self.record_match(rule);
            self.apply_setvars(&rule.setvars);
            self.apply_ctl(rule);

            if let Some(marker) = &rule.skip_after {
                if let Some(position) = self.rules.marker_position(marker) {
                    index = position + 1;
                    continue;
                }
            }

            match rule.disruptive {
                Some(Disruptive::Deny)
                | Some(Disruptive::Block)
                | Some(Disruptive::Drop)
                | Some(Disruptive::Redirect) => {
                    if self.mode == EngineMode::Blocking {
                        self.verdict = Verdict::Deny {
                            status: rule.status.unwrap_or(403),
                            rule_id: rule.id.unwrap_or(0),
                        };
                        return self.verdict.clone();
                    }
                }
                Some(Disruptive::Pass) | None => {}
            }

            index += 1;
        }

        self.completed = Some(phase);
        self.verdict.clone()
    }

    /// Whether a `ctl:` action has switched this rule off for the transaction.
    fn is_removed(&self, rule: &CompiledRule) -> bool {
        if let Some(id) = rule.id {
            if self.removed_ids.contains(&id) {
                return true;
            }
        }
        rule.tags.iter().any(|t| self.removed_tags.contains(t))
    }

    fn apply_ctl(&mut self, rule: &CompiledRule) {
        for ctl in &rule.ctl {
            match ctl {
                Ctl::RuleEngine(mode) => match mode {
                    // DetectionOnly and Off differ for a real engine; here both
                    // stop disruption, and Off also stops evaluation.
                    RuleEngineMode::Off => self.engine_off = true,
                    RuleEngineMode::DetectionOnly => self.mode = EngineMode::DetectionOnly,
                    RuleEngineMode::On => self.mode = EngineMode::Blocking,
                },
                Ctl::RuleRemoveById(spec) => {
                    for id in parse_id_range(spec) {
                        self.removed_ids.insert(id);
                    }
                }
                Ctl::RuleRemoveByTag(tag) => {
                    self.removed_tags.insert(tag.clone());
                }
                Ctl::RuleRemoveTargetById { rule, target } => self
                    .removed_targets
                    .push((RuleSelector::Id(rule.clone()), target.clone())),
                Ctl::RuleRemoveTargetByTag { tag, target } => self
                    .removed_targets
                    .push((RuleSelector::Tag(tag.clone()), target.clone())),
                // Audit logging is not implemented, so this changes nothing.
                Ctl::AuditEngine(_) => {}
                // Body handling is decided when the body arrives, which is
                // before any phase-2 rule can run.
                Ctl::ForceRequestBodyVariable(_) | Ctl::RequestBodyProcessor(_) => {}
            }
        }
    }

    /// Targets this rule must not inspect, per `ctl:ruleRemoveTarget*`.
    fn removed_targets_for(&self, rule: &CompiledRule) -> Vec<String> {
        self.removed_targets
            .iter()
            .filter(|(selector, _)| match selector {
                RuleSelector::Id(id) => {
                    rule.id.is_some_and(|rid| parse_id_range(id).contains(&rid))
                }
                RuleSelector::Tag(tag) => rule.tags.contains(tag),
            })
            .map(|(_, target)| target.clone())
            .collect()
    }

    /// Evaluate a rule, including every link of its chain.
    fn evaluate(&mut self, rule: &CompiledRule) -> bool {
        // A rule with no operator (SecAction) always matches.
        let Some(operator) = &rule.operator else {
            return true;
        };

        let excluded = self.removed_targets_for(rule);
        let Some(hit) = self.evaluate_step(Step {
            targets: &rule.targets,
            operator,
            negated: rule.negated,
            transformations: &rule.transformations,
            capture: rule.capture,
            multi_match: rule.multi_match,
            excluded: &excluded,
        }) else {
            return false;
        };

        self.vars.matched_var = hit.value.clone();
        self.vars.matched_var_name = hit.name.clone().into_bytes();
        self.vars.matched_vars.push(hit.name, hit.value);

        for link in &rule.chain {
            if !self.evaluate_link(link) {
                return false;
            }
        }
        true
    }

    fn evaluate_link(&mut self, link: &ChainLink) -> bool {
        let Some(operator) = &link.operator else {
            self.apply_setvars(&link.setvars);
            return true;
        };
        let Some(hit) = self.evaluate_step(Step {
            targets: &link.targets,
            operator,
            negated: link.negated,
            transformations: &link.transformations,
            capture: link.capture,
            multi_match: false,
            excluded: &[],
        }) else {
            return false;
        };
        self.vars.matched_var = hit.value.clone();
        self.vars.matched_var_name = hit.name.clone().into_bytes();
        self.apply_setvars(&link.setvars);
        true
    }

    /// Apply transformations to each target value and test the operator.
    ///
    /// Returns the first value that satisfied the operator, which is what
    /// `MATCHED_VAR` reports.
    fn evaluate_step(&mut self, step: Step<'_>) -> Option<Value> {
        let Step {
            targets,
            operator,
            negated,
            transformations,
            capture,
            multi_match,
            excluded,
        } = step;
        let mut values = self.vars.resolve(targets);
        if !excluded.is_empty() {
            values.retain(|v| !excluded.iter().any(|ex| v.name.eq_ignore_ascii_case(ex)));
        }
        let mut captures: Option<Vec<Vec<u8>>> = None;
        let mut hit: Option<Value> = None;

        for value in values {
            // `multiMatch` tests after every transformation, not only the last,
            // so a payload that is detectable at an intermediate decoding
            // stage is still caught.
            let mut candidates: Vec<Vec<u8>> = Vec::new();
            let mut current = value.value.clone();
            if multi_match {
                candidates.push(current.clone());
            }
            for t in transformations {
                current = t.apply(&current).into_owned();
                if multi_match {
                    candidates.push(current.clone());
                }
            }
            if !multi_match {
                candidates.push(current);
            }

            for candidate in candidates {
                let result = operator.evaluate(&candidate, &self.vars, capture);
                if result.matched != negated {
                    if capture && !result.captures.is_empty() {
                        captures = Some(result.captures);
                    }
                    hit = Some(Value {
                        name: value.name.clone(),
                        value: candidate,
                    });
                    break;
                }
            }
            if hit.is_some() {
                break;
            }
        }

        // Captures land in TX:0 through TX:9, as SecLang exposes them.
        if let Some(groups) = captures {
            for (i, group) in groups.iter().take(10).enumerate() {
                self.vars.tx_set(&i.to_string(), group.clone());
            }
        }
        hit
    }

    fn apply_setvars(&mut self, setvars: &[SetVarSpec]) {
        for spec in setvars {
            let name_bytes = spec.name.expand(&self.vars).into_owned();
            let Ok(name) = String::from_utf8(name_bytes) else {
                continue;
            };
            // `setvar` names are written `tx.foo`; the collection prefix is
            // not part of the variable name.
            let name = name
                .strip_prefix("tx.")
                .or_else(|| name.strip_prefix("TX."))
                .unwrap_or(&name)
                .to_string();

            match spec.op {
                SetVarOp::Delete => self.vars.tx_remove(&name),
                SetVarOp::Set => {
                    let value = match &spec.value {
                        Some(t) => t.expand(&self.vars).into_owned(),
                        None => b"1".to_vec(),
                    };
                    self.vars.tx_set(&name, value);
                }
                SetVarOp::Add | SetVarOp::Subtract => {
                    let operand = spec
                        .value
                        .as_ref()
                        .map(|t| t.expand(&self.vars).into_owned())
                        .unwrap_or_else(|| b"1".to_vec());
                    let delta = std::str::from_utf8(&operand)
                        .ok()
                        .and_then(|s| s.trim().parse::<i64>().ok())
                        .unwrap_or(0);
                    let current = self.vars.tx_number(&name);
                    let updated = match spec.op {
                        SetVarOp::Add => current.saturating_add(delta),
                        _ => current.saturating_sub(delta),
                    };
                    self.vars.tx_set(&name, updated.to_string().into_bytes());
                }
            }
        }
    }

    fn record_match(&mut self, rule: &CompiledRule) {
        let expand = |t: &Option<crate::macros::Template>| -> String {
            t.as_ref()
                .map(|t| String::from_utf8_lossy(&t.expand(&self.vars)).into_owned())
                .unwrap_or_default()
        };
        self.matches.push(RuleMatch {
            logged: !rule.nolog,
            id: rule.id,
            message: expand(&rule.msg),
            data: expand(&rule.logdata),
            tags: rule.tags.clone(),
            matched_name: String::from_utf8_lossy(&self.vars.matched_var_name).into_owned(),
        });
    }
}

/// Parse a `ctl:ruleRemoveById` operand, which is an id or an inclusive
/// `start-end` range.
fn parse_id_range(spec: &str) -> Vec<u32> {
    let spec = spec.trim();
    match spec.split_once('-') {
        Some((lo, hi)) => match (lo.trim().parse::<u32>(), hi.trim().parse::<u32>()) {
            (Ok(lo), Ok(hi)) if lo <= hi && hi - lo < 100_000 => (lo..=hi).collect(),
            _ => Vec::new(),
        },
        None => spec.parse::<u32>().map(|id| vec![id]).unwrap_or_default(),
    }
}

/// Split an `application/x-www-form-urlencoded` payload into pairs, decoding
/// percent escapes and `+`.
fn parse_urlencoded(input: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for pair in input.split(|b| *b == b'&' || *b == b';') {
        if pair.is_empty() {
            continue;
        }
        let (raw_name, raw_value) = match pair.iter().position(|b| *b == b'=') {
            Some(i) => (&pair[..i], &pair[i + 1..]),
            None => (pair, &[][..]),
        };
        let name = Transformation::UrlDecodeUni.apply(raw_name).into_owned();
        let value = Transformation::UrlDecodeUni.apply(raw_value).into_owned();
        out.push((String::from_utf8_lossy(&name).into_owned(), value));
    }
    out
}

/// Split a `Cookie` header into pairs.
fn parse_cookies(input: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for pair in input.split(|b| *b == b';') {
        let pair = trim_ascii(pair);
        if pair.is_empty() {
            continue;
        }
        let (name, value) = match pair.iter().position(|b| *b == b'=') {
            Some(i) => (&pair[..i], &pair[i + 1..]),
            None => (pair, &[][..]),
        };
        out.push((
            String::from_utf8_lossy(trim_ascii(name)).into_owned(),
            trim_ascii(value).to_vec(),
        ));
    }
    out
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = bytes {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = bytes {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::matcher::NoDataLoader;
    use crate::parse;

    /// Build a rule set from SecLang source.
    fn rules(source: &str) -> RuleSet {
        let directives = parse(source, "test.conf").expect("must parse");
        RuleSet::compile(&directives, &NoDataLoader).expect("must compile")
    }

    fn get<'r>(rules: &'r RuleSet, uri: &str) -> Transaction<'r> {
        let mut tx = Transaction::new(rules, EngineMode::Blocking);
        tx.process_uri("GET", uri, "HTTP/1.1");
        tx
    }

    #[test]
    fn a_matching_rule_denies() {
        let rs = rules(r#"SecRule ARGS "@rx attack" "id:1,phase:1,deny,status:403""#);
        let mut tx = get(&rs, "/?q=attack");
        assert_eq!(
            tx.process_request_headers(),
            Verdict::Deny {
                status: 403,
                rule_id: 1
            }
        );
    }

    #[test]
    fn a_non_matching_rule_allows() {
        let rs = rules(r#"SecRule ARGS "@rx attack" "id:1,phase:1,deny""#);
        let mut tx = get(&rs, "/?q=benign");
        assert_eq!(tx.process_request_headers(), Verdict::Allow);
    }

    #[test]
    fn detection_only_mode_records_without_denying() {
        let rs = rules(r#"SecRule ARGS "@rx attack" "id:1,phase:1,deny,msg:'hit'""#);
        let mut tx = Transaction::new(&rs, EngineMode::DetectionOnly);
        tx.process_uri("GET", "/?q=attack", "HTTP/1.1");
        assert_eq!(tx.process_request_headers(), Verdict::Allow);
        assert_eq!(tx.matches().len(), 1);
    }

    #[test]
    fn query_arguments_are_url_decoded() {
        let rs = rules(r#"SecRule ARGS "@rx <script>" "id:1,phase:1,deny""#);
        let mut tx = get(&rs, "/?q=%3Cscript%3E");
        assert!(matches!(tx.process_request_headers(), Verdict::Deny { .. }));
    }

    #[test]
    fn transformations_run_in_order_before_the_operator() {
        let rs = rules(
            r#"SecRule ARGS "@rx <script>" "id:1,phase:1,deny,t:none,t:htmlEntityDecode,t:lowercase""#,
        );
        let mut tx = get(&rs, "/?q=%26lt%3BSCRIPT%26gt%3B");
        assert!(matches!(tx.process_request_headers(), Verdict::Deny { .. }));
    }

    #[test]
    fn a_negated_operator_inverts_the_test() {
        let rs = rules(r#"SecRule REQUEST_METHOD "!@within GET HEAD" "id:1,phase:1,deny""#);
        let mut tx = get(&rs, "/");
        assert_eq!(tx.process_request_headers(), Verdict::Allow);

        let mut tx = Transaction::new(&rs, EngineMode::Blocking);
        tx.process_uri("DELETE", "/", "HTTP/1.1");
        assert!(matches!(tx.process_request_headers(), Verdict::Deny { .. }));
    }

    #[test]
    fn setvar_accumulates_an_anomaly_score() {
        let rs = rules(
            r#"
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.critical_score=5'"
SecRule ARGS "@rx attack" "id:2,phase:1,pass,setvar:'tx.anomaly_score=+%{tx.critical_score}'"
SecRule ARGS "@rx attack" "id:3,phase:1,pass,setvar:'tx.anomaly_score=+%{tx.critical_score}'"
"#,
        );
        let mut tx = get(&rs, "/?q=attack");
        tx.process_request_headers();
        assert_eq!(tx.anomaly_score("anomaly_score"), 10);
    }

    #[test]
    fn anomaly_scoring_then_blocking_works_end_to_end() {
        // The shape CRS uses: rules add score, a final rule denies on it.
        let rs = rules(
            r#"
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.threshold=5'"
SecRule ARGS "@rx attack" "id:2,phase:1,pass,setvar:'tx.score=+5'"
SecRule TX:SCORE "@ge %{tx.threshold}" "id:3,phase:1,deny,status:403,msg:'score exceeded'"
"#,
        );
        let mut tx = get(&rs, "/?q=attack");
        assert!(matches!(
            tx.process_request_headers(),
            Verdict::Deny { rule_id: 3, .. }
        ));

        let mut clean = get(&rs, "/?q=fine");
        assert_eq!(clean.process_request_headers(), Verdict::Allow);
    }

    #[test]
    fn setvar_subtract_and_delete_work() {
        let rs = rules(
            r#"
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.score=10'"
SecAction "id:2,phase:1,pass,nolog,setvar:'tx.score=-3'"
SecAction "id:3,phase:1,pass,nolog,setvar:'tx.gone=1'"
SecAction "id:4,phase:1,pass,nolog,setvar:!tx.gone"
"#,
        );
        let mut tx = get(&rs, "/");
        tx.process_request_headers();
        assert_eq!(tx.anomaly_score("score"), 7);
        assert_eq!(tx.vars.tx_get("gone"), None);
    }

    #[test]
    fn a_chain_requires_every_link_to_match() {
        let rs = rules(
            r#"
SecRule ARGS "@rx attack" "id:1,phase:1,deny,chain"
    SecRule REQUEST_METHOD "@streq POST"
"#,
        );
        // The starter matches but the chained link does not.
        let mut tx = get(&rs, "/?q=attack");
        assert_eq!(tx.process_request_headers(), Verdict::Allow);

        let mut tx = Transaction::new(&rs, EngineMode::Blocking);
        tx.process_uri("POST", "/?q=attack", "HTTP/1.1");
        assert!(matches!(tx.process_request_headers(), Verdict::Deny { .. }));
    }

    #[test]
    fn skip_after_jumps_past_a_marker() {
        let rs = rules(
            r#"
SecAction "id:1,phase:1,pass,nolog,skipAfter:PAST"
SecRule ARGS "@rx attack" "id:2,phase:1,deny"
SecMarker PAST
SecRule ARGS "@rx attack" "id:3,phase:1,pass,setvar:'tx.reached=1'"
"#,
        );
        let mut tx = get(&rs, "/?q=attack");
        // Rule 2 is skipped, so no denial; rule 3 runs.
        assert_eq!(tx.process_request_headers(), Verdict::Allow);
        assert_eq!(tx.vars.tx_get("reached"), Some(&b"1"[..]));
    }

    #[test]
    fn an_unknown_skip_after_target_is_a_compile_error() {
        let directives = parse(
            r#"SecAction "id:1,phase:1,pass,skipAfter:NOWHERE""#,
            "test.conf",
        )
        .unwrap();
        let err = RuleSet::compile(&directives, &NoDataLoader).unwrap_err();
        assert!(matches!(
            err,
            crate::engine::CompileError::UnknownMarker { .. }
        ));
    }

    #[test]
    fn a_dangling_chain_is_a_compile_error() {
        let directives = parse(
            r#"SecRule ARGS "@rx x" "id:1,phase:1,deny,chain""#,
            "test.conf",
        )
        .unwrap();
        let err = RuleSet::compile(&directives, &NoDataLoader).unwrap_err();
        assert!(matches!(
            err,
            crate::engine::CompileError::DanglingChain { .. }
        ));
    }

    #[test]
    fn captures_populate_tx_numbered_variables() {
        let rs = rules(
            r#"SecRule ARGS "@rx (\d+)-(\d+)" "id:1,phase:1,pass,capture,setvar:'tx.found=%{tx.1}'""#,
        );
        let mut tx = get(&rs, "/?q=10-20");
        tx.process_request_headers();
        assert_eq!(tx.vars.tx_get("0"), Some(&b"10-20"[..]));
        assert_eq!(tx.vars.tx_get("found"), Some(&b"10"[..]));
    }

    #[test]
    fn matched_var_name_reports_the_variable_that_matched() {
        let rs = rules(r#"SecRule ARGS "@rx attack" "id:1,phase:1,pass,msg:'hit'""#);
        let mut tx = get(&rs, "/?safe=ok&danger=attack");
        tx.process_request_headers();
        assert_eq!(tx.matches()[0].matched_name, "ARGS:danger");
    }

    #[test]
    fn logdata_and_msg_expand_macros() {
        let rs = rules(
            r#"SecRule ARGS "@rx (attack)" "id:1,phase:1,pass,capture,msg:'found',logdata:'Matched %{TX.0} in %{MATCHED_VAR_NAME}'""#,
        );
        let mut tx = get(&rs, "/?q=attack");
        tx.process_request_headers();
        assert_eq!(tx.matches()[0].data, "Matched attack in ARGS:q");
    }

    #[test]
    fn target_exclusions_remove_variables_from_inspection() {
        let rs = rules(r#"SecRule ARGS|!ARGS:allowed "@rx attack" "id:1,phase:1,deny""#);
        let mut tx = get(&rs, "/?allowed=attack");
        assert_eq!(tx.process_request_headers(), Verdict::Allow);

        let mut tx = get(&rs, "/?other=attack");
        assert!(matches!(tx.process_request_headers(), Verdict::Deny { .. }));
    }

    #[test]
    fn a_regex_selector_narrows_a_collection() {
        let rs = rules(r#"SecRule REQUEST_HEADERS:/^X-/ "@rx attack" "id:1,phase:1,deny""#);
        let mut tx = Transaction::new(&rs, EngineMode::Blocking);
        tx.process_uri("GET", "/", "HTTP/1.1");
        tx.add_request_header("User-Agent", "attack");
        assert_eq!(tx.process_request_headers(), Verdict::Allow);

        let mut tx = Transaction::new(&rs, EngineMode::Blocking);
        tx.process_uri("GET", "/", "HTTP/1.1");
        tx.add_request_header("X-Custom", "attack");
        assert!(matches!(tx.process_request_headers(), Verdict::Deny { .. }));
    }

    #[test]
    fn cookies_are_parsed_from_the_cookie_header() {
        let rs = rules(r#"SecRule REQUEST_COOKIES "@rx attack" "id:1,phase:1,deny""#);
        let mut tx = Transaction::new(&rs, EngineMode::Blocking);
        tx.process_uri("GET", "/", "HTTP/1.1");
        tx.add_request_header("Cookie", "session=abc; tracking=attack");
        assert!(matches!(tx.process_request_headers(), Verdict::Deny { .. }));
    }

    #[test]
    fn a_count_target_inspects_the_number_of_members() {
        let rs = rules(r#"SecRule &ARGS "@gt 2" "id:1,phase:1,deny""#);
        let mut tx = get(&rs, "/?a=1&b=2");
        assert_eq!(tx.process_request_headers(), Verdict::Allow);

        let mut tx = get(&rs, "/?a=1&b=2&c=3");
        assert!(matches!(tx.process_request_headers(), Verdict::Deny { .. }));
    }

    #[test]
    fn urlencoded_bodies_populate_args() {
        let rs = rules(r#"SecRule ARGS "@rx attack" "id:1,phase:2,deny""#);
        let mut tx = Transaction::new(&rs, EngineMode::Blocking);
        tx.process_uri("POST", "/", "HTTP/1.1");
        tx.process_request_headers();
        tx.set_request_body(b"q=attack", Some("application/x-www-form-urlencoded"));
        assert!(matches!(tx.process_request_body(), Verdict::Deny { .. }));
    }

    #[test]
    fn an_unparseable_body_sets_a_body_error_rather_than_passing() {
        // A format with no parser must not be silently treated as empty. CRS
        // blocks on REQBODY_ERROR, which is the mechanism SecLang provides.
        let rs = rules(
            r#"SecRule TX:REQBODY_ERROR "@eq 1" "id:1,phase:2,deny,msg:'body could not be parsed'""#,
        );
        let mut tx = Transaction::new(&rs, EngineMode::Blocking);
        tx.process_uri("POST", "/", "HTTP/1.1");
        tx.process_request_headers();
        tx.set_request_body(b"<x>attack</x>", Some("text/xml"));
        assert!(tx.body_error().is_some());
        assert!(matches!(tx.process_request_body(), Verdict::Deny { .. }));
    }

    #[test]
    fn later_phases_do_not_run_after_a_denial() {
        let rs = rules(
            r#"
SecRule ARGS "@rx attack" "id:1,phase:1,deny"
SecAction "id:2,phase:2,pass,nolog,setvar:'tx.phase2_ran=1'"
"#,
        );
        let mut tx = get(&rs, "/?q=attack");
        assert!(matches!(tx.process_request_headers(), Verdict::Deny { .. }));
        tx.process_request_body();
        assert_eq!(tx.vars.tx_get("phase2_ran"), None);
    }

    #[test]
    fn response_phases_inspect_response_variables() {
        let rs = rules(r#"SecRule RESPONSE_BODY "@rx secret" "id:1,phase:4,deny""#);
        let mut tx = get(&rs, "/");
        tx.process_request_headers();
        tx.process_request_body();
        tx.set_response_status(200);
        tx.process_response_headers();
        tx.set_response_body(b"this contains a secret");
        assert!(matches!(tx.process_response_body(), Verdict::Deny { .. }));
    }

    #[test]
    fn multi_match_tests_intermediate_transformation_results() {
        // Without multiMatch only the fully transformed value is tested. With
        // it, the value after each step is tested too.
        let rs = rules(
            r#"SecRule ARGS "@rx ^attack$" "id:1,phase:1,deny,multiMatch,t:none,t:lowercase""#,
        );
        let mut tx = get(&rs, "/?q=ATTACK");
        assert!(matches!(tx.process_request_headers(), Verdict::Deny { .. }));
    }

    #[test]
    fn a_count_target_respects_its_selector() {
        // Counting the whole collection instead of the selected member makes
        // every presence check true, which fires the rules that test for a
        // header being absent. That silently broke five CRS protocol rules.
        let rs = rules(r#"SecRule &REQUEST_HEADERS:Transfer-Encoding "@ge 1" "id:1,phase:1,deny""#);
        let mut tx = Transaction::new(&rs, EngineMode::Blocking);
        tx.process_uri("GET", "/", "HTTP/1.1");
        tx.add_request_header("Host", "example.test");
        tx.add_request_header("User-Agent", "curl");
        assert_eq!(tx.process_request_headers(), Verdict::Allow);

        let mut tx = Transaction::new(&rs, EngineMode::Blocking);
        tx.process_uri("GET", "/", "HTTP/1.1");
        tx.add_request_header("Transfer-Encoding", "chunked");
        assert!(matches!(tx.process_request_headers(), Verdict::Deny { .. }));
    }

    #[test]
    fn counting_an_absent_tx_variable_gives_zero() {
        // How CRS installs its defaults: `&TX:x "@eq 0"` then setvar.
        let rs = rules(
            r#"
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.other=1'"
SecRule &TX:allowed_methods "@eq 0" "id:2,phase:1,pass,nolog,setvar:'tx.allowed_methods=GET HEAD'"
SecRule REQUEST_METHOD "!@within %{tx.allowed_methods}" "id:3,phase:1,deny"
"#,
        );
        let mut tx = get(&rs, "/");
        assert_eq!(tx.process_request_headers(), Verdict::Allow);
        assert_eq!(tx.vars.tx_get("allowed_methods"), Some(&b"GET HEAD"[..]));
    }

    #[test]
    fn block_resolves_to_the_default_action_not_to_deny() {
        // ModSecurity's built-in default is `pass`, and CRS depends on it: its
        // `block` rules are meant to score, with the denial coming from an
        // explicit `deny` later. Treating `block` as deny makes the first
        // matching rule terminate the request and defeats anomaly scoring.
        let rs = rules(
            r#"
SecRule ARGS "@rx attack" "id:1,phase:1,block,setvar:'tx.score=+5'"
SecRule TX:SCORE "@ge 10" "id:2,phase:1,deny"
"#,
        );
        let mut tx = get(&rs, "/?q=attack");
        assert_eq!(tx.process_request_headers(), Verdict::Allow);
        assert_eq!(tx.anomaly_score("score"), 5);
    }

    #[test]
    fn sec_default_action_makes_block_disruptive() {
        let rs = rules(
            r#"
SecDefaultAction "phase:1,log,auditlog,deny,status:406"
SecRule ARGS "@rx attack" "id:1,phase:1,block"
"#,
        );
        let mut tx = get(&rs, "/?q=attack");
        assert_eq!(
            tx.process_request_headers(),
            Verdict::Deny {
                status: 406,
                rule_id: 1
            }
        );
    }

    #[test]
    fn a_rule_with_no_phase_defaults_to_phase_two() {
        let rs = rules(r#"SecRule ARGS "@rx attack" "id:1,deny""#);
        let mut tx = get(&rs, "/?q=attack");
        assert_eq!(tx.process_request_headers(), Verdict::Allow);
        assert!(matches!(tx.process_request_body(), Verdict::Deny { .. }));
    }
}
