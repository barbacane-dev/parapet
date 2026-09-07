//! The rule AST.
//!
//! A parsed rule set is data, not behaviour: parsing produces this tree, and
//! compilation turns it into an evaluable program. Keeping the two apart is
//! what lets an embedder compile ahead of time.

use crate::action::Action;
use crate::operator::Operator;

/// One SecLang directive.
#[derive(Debug, Clone, PartialEq)]
pub enum Directive {
    /// `SecRule TARGETS "OPERATOR" "ACTIONS"`
    Rule(Rule),
    /// `SecAction "ACTIONS"`, a rule that always matches.
    Action(Rule),
    /// `SecMarker NAME`, a `skipAfter` jump destination.
    Marker(String),
    /// `SecComponentSignature SIGNATURE`
    ComponentSignature(String),
    /// `SecDefaultAction "phase:2,log,auditlog,pass"`
    ///
    /// Sets what `block` resolves to for rules that follow it. CRS relies on
    /// this: its 311 `block` rules are meant to score, not to deny, and the
    /// denial comes from the explicit `deny` in the blocking-evaluation rules.
    DefaultAction {
        /// The phase the default applies to.
        phase: crate::Phase,
        /// The actions it sets.
        actions: Vec<crate::action::Action>,
    },
}

/// A rule: what to inspect, what to test, what to do about it.
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    /// The variables to inspect. Empty for `SecAction`.
    pub targets: Vec<Target>,
    /// The test to apply. `None` for `SecAction`, which always matches.
    pub operator: Option<Operator>,
    /// Whether the operator's result is inverted (`!@rx ...`).
    pub negated: bool,
    /// What to do when the rule matches.
    pub actions: Vec<Action>,
    /// 1-based line in the source file, for diagnostics.
    pub line: usize,
}

impl Rule {
    /// The rule's `id:` action, if it declares one. Chained rules carry the id
    /// only on the chain starter.
    pub fn id(&self) -> Option<u32> {
        self.actions.iter().find_map(|a| match a {
            Action::Id(id) => Some(*id),
            _ => None,
        })
    }

    /// Whether this rule starts or continues a chain.
    pub fn is_chained(&self) -> bool {
        self.actions.iter().any(|a| matches!(a, Action::Chain))
    }
}

/// A variable to inspect, such as `ARGS`, `ARGS:id` or `!REQUEST_COOKIES:/^__/`.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    /// The collection being addressed.
    pub collection: Collection,
    /// Which members of the collection, when narrowed.
    pub selector: Option<Selector>,
    /// `!` prefix: remove these members from the set under inspection.
    pub exclusion: bool,
    /// `&` prefix: inspect the member count rather than the values.
    pub count: bool,
}

/// How a target narrows a collection.
#[derive(Debug, Clone, PartialEq)]
pub enum Selector {
    /// `ARGS:username`, an exact member name.
    Name(String),
    /// `REQUEST_HEADERS:/^X-/`, a pattern over member names.
    Regex(String),
    /// `XML:/*`, an XPath expression. Only the `XML` collection is selected
    /// this way, and the expression is kept as authored.
    XPath(String),
}

/// The collections CRS addresses.
///
/// SecLang defines more. An unlisted collection fails parsing rather than
/// being ignored, because a target nobody inspects is a rule that cannot fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum Collection {
    Args,
    ArgsCombinedSize,
    ArgsGet,
    ArgsGetNames,
    ArgsNames,
    Files,
    FilesCombinedSize,
    FilesNames,
    MatchedVar,
    MatchedVars,
    MultipartPartHeaders,
    QueryString,
    ReqbodyProcessor,
    RemoteAddr,
    RequestBasename,
    RequestBody,
    RequestCookies,
    RequestCookiesNames,
    RequestFilename,
    RequestHeaders,
    RequestHeadersNames,
    RequestLine,
    RequestMethod,
    RequestProtocol,
    RequestUri,
    RequestUriRaw,
    ResponseBody,
    ResponseHeaders,
    ResponseStatus,
    Tx,
    UniqueId,
    Xml,
}

impl Collection {
    /// Parse a collection name. Case-insensitive, as SecLang is.
    pub fn parse(name: &str) -> Option<Self> {
        use Collection::*;
        Some(match name.to_ascii_uppercase().as_str() {
            "ARGS" => Args,
            "ARGS_COMBINED_SIZE" => ArgsCombinedSize,
            "ARGS_GET" => ArgsGet,
            "ARGS_GET_NAMES" => ArgsGetNames,
            "ARGS_NAMES" => ArgsNames,
            "FILES" => Files,
            "FILES_COMBINED_SIZE" => FilesCombinedSize,
            "FILES_NAMES" => FilesNames,
            "MATCHED_VAR" => MatchedVar,
            "MATCHED_VARS" => MatchedVars,
            "MULTIPART_PART_HEADERS" => MultipartPartHeaders,
            "QUERY_STRING" => QueryString,
            "REQBODY_PROCESSOR" => ReqbodyProcessor,
            "REMOTE_ADDR" => RemoteAddr,
            "REQUEST_BASENAME" => RequestBasename,
            "REQUEST_BODY" => RequestBody,
            "REQUEST_COOKIES" => RequestCookies,
            "REQUEST_COOKIES_NAMES" => RequestCookiesNames,
            "REQUEST_FILENAME" => RequestFilename,
            "REQUEST_HEADERS" => RequestHeaders,
            "REQUEST_HEADERS_NAMES" => RequestHeadersNames,
            "REQUEST_LINE" => RequestLine,
            "REQUEST_METHOD" => RequestMethod,
            "REQUEST_PROTOCOL" => RequestProtocol,
            "REQUEST_URI" => RequestUri,
            "REQUEST_URI_RAW" => RequestUriRaw,
            "RESPONSE_BODY" => ResponseBody,
            "RESPONSE_HEADERS" => ResponseHeaders,
            "RESPONSE_STATUS" => ResponseStatus,
            "TX" => Tx,
            "UNIQUE_ID" => UniqueId,
            "XML" => Xml,
            _ => return None,
        })
    }
}

/// Rule severity, as SecLang defines it (syslog levels 0 through 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(missing_docs)]
pub enum Severity {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl Severity {
    /// Parse a severity by name or by numeric level.
    pub fn parse(s: &str) -> Option<Self> {
        use Severity::*;
        Some(match s.to_ascii_uppercase().as_str() {
            "EMERGENCY" | "0" => Emergency,
            "ALERT" | "1" => Alert,
            "CRITICAL" | "2" => Critical,
            "ERROR" | "3" => Error,
            "WARNING" | "4" => Warning,
            "NOTICE" | "5" => Notice,
            "INFO" | "6" => Info,
            "DEBUG" | "7" => Debug,
            _ => return None,
        })
    }
}
