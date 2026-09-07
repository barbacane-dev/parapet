//! A SecLang rule engine in pure Rust, compatible with the OWASP Core Rule Set.
//!
//! Parapet parses SecLang, compiles a rule set into an evaluable program, and
//! runs HTTP transactions through it across the five SecLang phases. It has no
//! C or C++ dependency, no garbage collector, and no FFI.
//!
//! # Design commitments
//!
//! **Compilation is separate from evaluation.** A rule set is parsed and
//! compiled once, into a program that holds compiled regexes and multi-pattern
//! automata. Evaluation borrows that program. Callers that compile ahead of
//! time (a build step, a sealed artifact) pay no rule-compilation cost at
//! request time.
//!
//! **An unrecognised construct is an error, never a skip.** A directive,
//! operator, transformation or action that Parapet does not implement fails
//! compilation. A rule set that silently loses a rule it could not parse turns
//! that rule into a bypass, so partial understanding is not an acceptable
//! outcome for a security control.
//!
//! **Conformance is measured, not asserted.** Compatibility means passing the
//! Core Rule Set's own regression corpus. See `crates/parapet-conformance`.
//!
//! # Status
//!
//! Early. The parser ([`parse`]) and the `@rx` compatibility layer
//! ([`regex_compat`]) are implemented and verified against CRS v4.9.0. The
//! evaluation engine is not written yet: nothing here can inspect a request.
//! See the repository README for the scope inventory and the order of work.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod action;
pub mod collections;
pub mod engine;
pub mod json;
pub mod macros;
pub mod matcher;
pub mod operator;
pub mod parse;
pub mod regex_compat;
pub mod rule;
pub mod transaction;
pub mod transform;
pub mod xml;

pub use engine::{CompileError, RuleSet};
pub use macros::{MacroContext, Template};
pub use matcher::{CompiledOperator, DataLoader, DirDataLoader, NoDataLoader};
pub use parse::{parse, parse_all, ParseError};
pub use rule::{Directive, Rule};
pub use transaction::{EngineMode, Transaction};

/// Whether a transaction may proceed.
///
/// The disruptive outcome of evaluating a rule set, independent of any
/// particular HTTP server or proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No rule demanded interruption.
    Allow,
    /// A rule interrupted the transaction.
    Deny {
        /// The HTTP status the rule asked for.
        status: u16,
        /// The id of the rule that interrupted.
        rule_id: u32,
    },
}

/// The SecLang evaluation phases.
///
/// CRS v4.9.0 distributes its rules across all five: 170 rules in
/// [`Phase::RequestHeaders`], 272 in [`Phase::RequestBody`], 39 in
/// [`Phase::ResponseHeaders`], 100 in [`Phase::ResponseBody`] and 13 in
/// [`Phase::Logging`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Phase {
    /// Phase 1.
    RequestHeaders = 1,
    /// Phase 2.
    RequestBody = 2,
    /// Phase 3.
    ResponseHeaders = 3,
    /// Phase 4.
    ResponseBody = 4,
    /// Phase 5.
    Logging = 5,
}
