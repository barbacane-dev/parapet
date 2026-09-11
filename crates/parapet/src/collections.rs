//! Transaction variables and how a [`Target`] resolves against them.
//!
//! SecLang collections are ordered and may hold duplicate names: a query
//! string can repeat a parameter, and a rule has to see every occurrence.
//! Resolution therefore yields `(name, value)` pairs in order rather than a
//! map lookup, which is also what `MATCHED_VAR_NAME` reports.

use std::borrow::Cow;

use crate::macros::MacroContext;
use crate::rule::Collection;

/// A target whose member-selector is compiled, ready to resolve without any
/// per-request work.
///
/// The parsed [`crate::rule::Target`] keeps its selector as a string so the
/// rule set stays serialisable; compilation turns it into this, where a regex
/// selector is a compiled automaton rather than a pattern to rebuild on every
/// resolution. A rule set with many regex selectors resolved thousands of
/// values per request, and recompiling the selector for each one measured as
/// the dominant cost of inspection.
#[derive(Debug, Clone)]
pub struct CompiledTarget {
    /// The collection to read.
    pub collection: Collection,
    /// Which members to keep, if narrowed.
    pub selector: Option<CompiledSelector>,
    /// A leading `!`: remove these members from the result.
    pub exclusion: bool,
    /// A leading `&`: inspect the member count, not the values.
    pub count: bool,
}

/// A member-selector, compiled.
#[derive(Debug, Clone)]
pub enum CompiledSelector {
    /// `ARGS:username`, an exact member name.
    Name(String),
    /// `REQUEST_HEADERS:/^X-/`, compiled once.
    Regex(regex::Regex),
    /// `XML:/*`, an XPath expression, kept as authored.
    XPath(String),
}

/// One resolved member of a collection.
///
/// Borrows its bytes from the transaction's variables. Every rule resolves its
/// targets, so with 591 CRS rules and a handful of arguments a cloning
/// resolver copies tens of thousands of small buffers per request, which
/// measured as the dominant cost of inspection. Only the value that actually
/// matches is copied, once, by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value<'a> {
    /// The fully qualified name, such as `ARGS:id`, as `MATCHED_VAR_NAME`
    /// reports it. Built for qualified members, borrowed for scalars.
    pub name: Cow<'a, str>,
    /// The member's value. Borrowed for stored variables, owned only for
    /// computed ones such as `&ARGS` counts and `*_COMBINED_SIZE`.
    pub value: Cow<'a, [u8]>,
}

/// A resolved value with its bytes owned, for the one value a rule matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedValue {
    /// The fully qualified name.
    pub name: String,
    /// The member's value, after transformations.
    pub value: Vec<u8>,
}

/// An ordered multimap preserving insertion order and duplicate names.
#[derive(Debug, Clone, Default)]
pub struct Multimap {
    entries: Vec<(String, Vec<u8>)>,
}

impl Multimap {
    /// Append an entry.
    pub fn push(&mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) {
        self.entries.push((name.into(), value.into()));
    }

    /// Every entry, in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.entries.iter().map(|(n, v)| (n.as_str(), v.as_slice()))
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map holds nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Combined byte length of all values, for the `*_COMBINED_SIZE` variables.
    pub fn combined_size(&self) -> usize {
        self.entries.iter().map(|(_, v)| v.len()).sum()
    }
}

/// Why a body could not be processed.
///
/// SecLang surfaces this as `REQBODY_ERROR`, and CRS has rules that block on
/// it. That is the correct home for "this body is in a format the engine
/// cannot inspect": the request is refused rather than passed uninspected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyError {
    /// The body is in a format with no parser yet.
    UnsupportedFormat(&'static str),
    /// The body was malformed for its declared type.
    Malformed(String),
}

/// All variables visible to a rule.
#[derive(Debug, Clone, Default)]
pub struct Variables {
    /// `ARGS_GET`, from the query string.
    pub args_get: Multimap,
    /// `ARGS_POST`, from a parsed request body.
    pub args_post: Multimap,
    /// `REQUEST_HEADERS`
    pub request_headers: Multimap,
    /// `REQUEST_COOKIES`
    pub request_cookies: Multimap,
    /// `RESPONSE_HEADERS`
    pub response_headers: Multimap,
    /// `TX`, the rule-writable scratch collection.
    pub tx: Multimap,
    /// `FILES`, from a multipart body.
    pub files: Multimap,
    /// `MULTIPART_PART_HEADERS`, keyed by header name, valued with the whole
    /// raw header line. CRS matches `^content-type\s*:\s*(.*)$` against the
    /// value, so the name has to stay in it.
    pub multipart_part_headers: Multimap,
    /// `XML:/*`, element text content from a parsed XML body.
    pub xml_elements: Multimap,
    /// `XML://@*`, attribute values from a parsed XML body.
    pub xml_attributes: Multimap,

    /// `REQUEST_METHOD`
    pub request_method: Vec<u8>,
    /// `REQUEST_URI`, path plus query.
    pub request_uri: Vec<u8>,
    /// `REQUEST_URI_RAW`, before any normalisation.
    pub request_uri_raw: Vec<u8>,
    /// `REQUEST_LINE`
    pub request_line: Vec<u8>,
    /// `REQUEST_PROTOCOL`
    pub request_protocol: Vec<u8>,
    /// `REQUEST_FILENAME`, the path with no query string.
    pub request_filename: Vec<u8>,
    /// `REQUEST_BASENAME`, the last path segment.
    pub request_basename: Vec<u8>,
    /// `QUERY_STRING`
    pub query_string: Vec<u8>,
    /// `REQUEST_BODY`
    pub request_body: Vec<u8>,
    /// `RESPONSE_BODY`
    pub response_body: Vec<u8>,
    /// `RESPONSE_STATUS`
    pub response_status: Vec<u8>,
    /// `REMOTE_ADDR`
    pub remote_addr: Vec<u8>,
    /// `UNIQUE_ID`
    pub unique_id: Vec<u8>,
    /// `REQBODY_PROCESSOR`
    pub reqbody_processor: Vec<u8>,
    /// Total bytes of uploaded file content, for `FILES_COMBINED_SIZE`. The
    /// `FILES` collection holds filenames, so its own size is not the answer.
    pub files_content_size: usize,

    /// `MATCHED_VAR`, the value that satisfied the last operator.
    pub matched_var: Vec<u8>,
    /// `MATCHED_VAR_NAME`
    pub matched_var_name: Vec<u8>,
    /// `MATCHED_VARS`, every value that matched in the current rule.
    pub matched_vars: Multimap,
}

impl Variables {
    /// Read a `TX` entry, which is where rules keep their state.
    pub fn tx_get(&self, name: &str) -> Option<&[u8]> {
        self.tx
            .entries
            .iter()
            .rev()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }

    /// Write a `TX` entry, replacing any existing one.
    pub fn tx_set(&mut self, name: &str, value: Vec<u8>) {
        if let Some(slot) = self
            .tx
            .entries
            .iter_mut()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
        {
            slot.1 = value;
            return;
        }
        self.tx.entries.push((name.to_string(), value));
    }

    /// Remove a `TX` entry.
    pub fn tx_remove(&mut self, name: &str) {
        self.tx
            .entries
            .retain(|(n, _)| !n.eq_ignore_ascii_case(name));
    }

    /// Read a `TX` entry as a number, treating unset and unparsable as 0, as
    /// SecLang does.
    pub fn tx_number(&self, name: &str) -> i64 {
        self.tx_get(name)
            .and_then(|v| std::str::from_utf8(v).ok())
            .and_then(|s| s.trim().parse::<i64>().ok())
            .unwrap_or(0)
    }

    /// Resolve a target list to the values a rule should inspect.
    ///
    /// Exclusions (`!ARGS:x`) are applied after collection, so order within
    /// the target list does not matter, matching SecLang.
    pub fn resolve(&self, targets: &[CompiledTarget]) -> Vec<Value<'_>> {
        let mut out: Vec<Value<'_>> = Vec::new();
        let mut excluded: Vec<(Collection, Option<&CompiledSelector>)> = Vec::new();

        for target in targets {
            if target.exclusion {
                excluded.push((target.collection, target.selector.as_ref()));
                continue;
            }
            self.resolve_one(target, &mut out);
        }

        if !excluded.is_empty() {
            out.retain(|value| {
                !excluded.iter().any(|(collection, selector)| {
                    let prefix = collection_name(*collection);
                    // Match the collection exactly, not by string prefix: a
                    // value is named `PREFIX` (a scalar) or `PREFIX:member` (a
                    // map). A bare `starts_with(prefix)` would let `!ARGS` also
                    // exclude `ARGS_GET:x` and `ARGS_NAMES:x`, since those names
                    // begin with "ARGS".
                    let member = match value.name.strip_prefix(prefix) {
                        Some("") => None,
                        Some(rest) => match rest.strip_prefix(':') {
                            Some(member) => Some(member),
                            // A longer collection name that merely starts with
                            // `prefix`, such as ARGS_GET against ARGS.
                            None => return false,
                        },
                        None => return false,
                    };
                    match (selector, member) {
                        // Whole-collection exclusion: every member of it.
                        (None, _) => true,
                        // A selector cannot match a scalar, which has no member.
                        (Some(_), None) => false,
                        (Some(CompiledSelector::Name(n)), Some(member)) => {
                            member.eq_ignore_ascii_case(n)
                        }
                        (Some(CompiledSelector::Regex(re)), Some(member)) => re.is_match(member),
                        // An XPath exclusion cannot be evaluated without an
                        // XML tree, and XML is never populated yet.
                        (Some(CompiledSelector::XPath(_)), _) => false,
                    }
                })
            });
        }
        out
    }

    fn resolve_one<'a>(&'a self, target: &CompiledTarget, out: &mut Vec<Value<'a>>) {
        use Collection::*;
        let prefix = collection_name(target.collection);

        // `&COLLECTION` inspects the member count, not the values.
        if target.count {
            let count = self.count_of(target);
            // A count is computed, so it has nowhere to borrow from. It is one
            // small allocation per count target, not per value.
            out.push(Value {
                name: Cow::Borrowed(prefix),
                value: Cow::Owned(count.to_string().into_bytes()),
            });
            return;
        }

        match target.collection {
            Args => {
                push_map(out, prefix, &self.args_get, target.selector.as_ref());
                push_map(out, prefix, &self.args_post, target.selector.as_ref());
            }
            ArgsGet => push_map(out, prefix, &self.args_get, target.selector.as_ref()),
            ArgsNames => push_names(out, prefix, [&self.args_get, &self.args_post]),
            ArgsGetNames => push_names(out, prefix, [&self.args_get]),
            RequestHeaders => {
                push_map(out, prefix, &self.request_headers, target.selector.as_ref())
            }
            RequestHeadersNames => push_names(out, prefix, [&self.request_headers]),
            RequestCookies => {
                push_map(out, prefix, &self.request_cookies, target.selector.as_ref())
            }
            RequestCookiesNames => push_names(out, prefix, [&self.request_cookies]),
            ResponseHeaders => push_map(
                out,
                prefix,
                &self.response_headers,
                target.selector.as_ref(),
            ),
            Tx => push_map(out, prefix, &self.tx, target.selector.as_ref()),
            Files => push_map(out, prefix, &self.files, target.selector.as_ref()),
            FilesNames => push_names(out, prefix, [&self.files]),
            MatchedVars => push_map(out, prefix, &self.matched_vars, target.selector.as_ref()),

            ArgsCombinedSize => push_computed(
                out,
                prefix,
                self.args_get.combined_size() + self.args_post.combined_size(),
            ),
            FilesCombinedSize => push_computed(out, prefix, self.files_content_size),

            RequestMethod => push_scalar(out, prefix, &self.request_method),
            RequestUri => push_scalar(out, prefix, &self.request_uri),
            RequestUriRaw => push_scalar(out, prefix, &self.request_uri_raw),
            RequestLine => push_scalar(out, prefix, &self.request_line),
            RequestProtocol => push_scalar(out, prefix, &self.request_protocol),
            RequestFilename => push_scalar(out, prefix, &self.request_filename),
            RequestBasename => push_scalar(out, prefix, &self.request_basename),
            QueryString => push_scalar(out, prefix, &self.query_string),
            RequestBody => push_scalar(out, prefix, &self.request_body),
            ResponseBody => push_scalar(out, prefix, &self.response_body),
            ResponseStatus => push_scalar(out, prefix, &self.response_status),
            RemoteAddr => push_scalar(out, prefix, &self.remote_addr),
            UniqueId => push_scalar(out, prefix, &self.unique_id),
            ReqbodyProcessor => push_scalar(out, prefix, &self.reqbody_processor),
            MatchedVar => push_scalar(out, prefix, &self.matched_var),

            // CRS addresses XML with exactly two XPath expressions. Anything
            // else is refused at compile time, so reaching here with another
            // form is impossible rather than silently empty.
            Xml => match target.selector.as_ref() {
                Some(CompiledSelector::XPath(expr)) if expr.trim() == "/*" => {
                    push_map(out, prefix, &self.xml_elements, None)
                }
                Some(CompiledSelector::XPath(expr)) if expr.trim() == "//@*" => {
                    push_map(out, prefix, &self.xml_attributes, None)
                }
                _ => {}
            },
            MultipartPartHeaders => push_map(
                out,
                prefix,
                &self.multipart_part_headers,
                target.selector.as_ref(),
            ),
        }
    }

    /// How many members a `&COLLECTION` target sees.
    ///
    /// The selector matters: `&REQUEST_HEADERS:Transfer-Encoding` asks whether
    /// that one header is present, not how many headers there are. Counting
    /// the whole collection instead makes every presence check true, which
    /// silently fires the rules that test for a header being absent.
    fn count_of(&self, target: &CompiledTarget) -> usize {
        let mut resolved = Vec::new();
        self.resolve_one(
            &CompiledTarget {
                collection: target.collection,
                selector: target.selector.clone(),
                exclusion: false,
                count: false,
            },
            &mut resolved,
        );
        if is_map_backed(target.collection) {
            // A present member counts even when its value is empty.
            resolved.len()
        } else {
            // A scalar counts as one when it is set.
            resolved.iter().filter(|v| !v.value.is_empty()).count()
        }
    }
}

/// Whether a collection holds named members rather than a single value.
fn is_map_backed(collection: Collection) -> bool {
    use Collection::*;
    matches!(
        collection,
        Args | ArgsGet
            | ArgsGetNames
            | ArgsNames
            | Files
            | FilesNames
            | MatchedVars
            | MultipartPartHeaders
            | RequestCookies
            | RequestCookiesNames
            | RequestHeaders
            | RequestHeadersNames
            | ResponseHeaders
            | Tx
            | Xml
    )
}

impl MacroContext for Variables {
    fn lookup(&self, name: &str) -> Option<Cow<'_, [u8]>> {
        let lower = name.to_ascii_lowercase();
        if let Some(member) = lower
            .strip_prefix("tx.")
            .or_else(|| lower.strip_prefix("tx:"))
        {
            return self.tx_get(member).map(Cow::Borrowed);
        }
        Some(Cow::Borrowed(match lower.as_str() {
            "matched_var" => &self.matched_var,
            "matched_var_name" => &self.matched_var_name,
            "request_method" => &self.request_method,
            "request_uri" => &self.request_uri,
            "request_filename" => &self.request_filename,
            "request_basename" => &self.request_basename,
            "query_string" => &self.query_string,
            "request_line" => &self.request_line,
            "request_protocol" => &self.request_protocol,
            "remote_addr" => &self.remote_addr,
            "unique_id" => &self.unique_id,
            "response_status" => &self.response_status,
            _ => return None,
        }))
    }
}

/// A value the engine computes rather than stores, so it must be owned. One
/// small allocation per count or size target, not per inspected value.
fn push_computed<'a>(out: &mut Vec<Value<'a>>, name: &'a str, value: usize) {
    out.push(Value {
        name: Cow::Borrowed(name),
        value: Cow::Owned(value.to_string().into_bytes()),
    });
}

fn push_scalar<'a>(out: &mut Vec<Value<'a>>, name: &'a str, value: &'a [u8]) {
    out.push(Value {
        name: Cow::Borrowed(name),
        value: Cow::Borrowed(value),
    });
}

fn push_map<'a>(
    out: &mut Vec<Value<'a>>,
    prefix: &'a str,
    map: &'a Multimap,
    selector: Option<&CompiledSelector>,
) {
    for (name, value) in map.iter() {
        let keep = match selector {
            None => true,
            Some(CompiledSelector::Name(want)) => name.eq_ignore_ascii_case(want),
            Some(CompiledSelector::Regex(re)) => re.is_match(name),
            Some(CompiledSelector::XPath(_)) => false,
        };
        if keep {
            out.push(Value {
                name: Cow::Owned(format!("{prefix}:{name}")),
                value: Cow::Borrowed(value),
            });
        }
    }
}

/// `*_NAMES` collections inspect the member names as values.
fn push_names<'a, const N: usize>(
    out: &mut Vec<Value<'a>>,
    prefix: &'a str,
    maps: [&'a Multimap; N],
) {
    for map in maps {
        for (name, _) in map.iter() {
            out.push(Value {
                name: Cow::Owned(format!("{prefix}:{name}")),
                // A *_NAMES collection inspects the name as the value, and the
                // name is already stored, so this borrows too.
                value: Cow::Borrowed(name.as_bytes()),
            });
        }
    }
}

/// The canonical SecLang name of a collection.
pub fn collection_name(collection: Collection) -> &'static str {
    use Collection::*;
    match collection {
        Args => "ARGS",
        ArgsCombinedSize => "ARGS_COMBINED_SIZE",
        ArgsGet => "ARGS_GET",
        ArgsGetNames => "ARGS_GET_NAMES",
        ArgsNames => "ARGS_NAMES",
        Files => "FILES",
        FilesCombinedSize => "FILES_COMBINED_SIZE",
        FilesNames => "FILES_NAMES",
        MatchedVar => "MATCHED_VAR",
        MatchedVars => "MATCHED_VARS",
        MultipartPartHeaders => "MULTIPART_PART_HEADERS",
        QueryString => "QUERY_STRING",
        ReqbodyProcessor => "REQBODY_PROCESSOR",
        RemoteAddr => "REMOTE_ADDR",
        RequestBasename => "REQUEST_BASENAME",
        RequestBody => "REQUEST_BODY",
        RequestCookies => "REQUEST_COOKIES",
        RequestCookiesNames => "REQUEST_COOKIES_NAMES",
        RequestFilename => "REQUEST_FILENAME",
        RequestHeaders => "REQUEST_HEADERS",
        RequestHeadersNames => "REQUEST_HEADERS_NAMES",
        RequestLine => "REQUEST_LINE",
        RequestMethod => "REQUEST_METHOD",
        RequestProtocol => "REQUEST_PROTOCOL",
        RequestUri => "REQUEST_URI",
        RequestUriRaw => "REQUEST_URI_RAW",
        ResponseBody => "RESPONSE_BODY",
        ResponseHeaders => "RESPONSE_HEADERS",
        ResponseStatus => "RESPONSE_STATUS",
        Tx => "TX",
        UniqueId => "UNIQUE_ID",
        Xml => "XML",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn target(collection: Collection, selector: Option<CompiledSelector>) -> CompiledTarget {
        CompiledTarget {
            collection,
            selector,
            exclusion: false,
            count: false,
        }
    }

    /// A `Variables` with every collection and scalar populated, so resolution
    /// of any target has something to return.
    fn populated() -> Variables {
        let mut v = Variables::default();
        v.args_get.push("a", &b"1"[..]);
        v.args_post.push("b", &b"2"[..]);
        v.request_headers.push("User-Agent", &b"curl"[..]);
        v.request_cookies.push("sid", &b"xyz"[..]);
        v.response_headers.push("Server", &b"nginx"[..]);
        v.tx.push("score", &b"5"[..]);
        v.files.push("upload", &b"evil.php"[..]);
        v.multipart_part_headers
            .push("Content-Type", &b"text/plain"[..]);
        v.xml_elements.push("a", &b"text"[..]);
        v.xml_attributes.push("attr", &b"val"[..]);
        v.matched_vars.push("ARGS:a", &b"1"[..]);
        v.request_method = b"GET".to_vec();
        v.request_uri = b"/p?q=1".to_vec();
        v.request_uri_raw = b"/p?q=1".to_vec();
        v.request_line = b"GET /p?q=1 HTTP/1.1".to_vec();
        v.request_protocol = b"HTTP/1.1".to_vec();
        v.request_filename = b"/p".to_vec();
        v.request_basename = b"p".to_vec();
        v.query_string = b"q=1".to_vec();
        v.request_body = b"body".to_vec();
        v.response_body = b"resp".to_vec();
        v.response_status = b"200".to_vec();
        v.remote_addr = b"203.0.113.7".to_vec();
        v.unique_id = b"uid".to_vec();
        v.reqbody_processor = b"URLENCODED".to_vec();
        v.files_content_size = 8;
        v.matched_var = b"1".to_vec();
        v
    }

    fn names(values: &[Value<'_>]) -> Vec<String> {
        values.iter().map(|v| v.name.to_string()).collect()
    }

    #[test]
    fn multimap_reports_length_size_and_emptiness() {
        let mut m = Multimap::default();
        assert!(m.is_empty());
        m.push("a", &b"12"[..]);
        m.push("b", &b"345"[..]);
        assert_eq!(m.len(), 2);
        assert!(!m.is_empty());
        assert_eq!(m.combined_size(), 5);
    }

    #[test]
    fn every_scalar_collection_resolves_to_its_value() {
        use Collection::*;
        let v = populated();
        for (collection, expected) in [
            (RequestMethod, "GET"),
            (RequestUri, "/p?q=1"),
            (RequestUriRaw, "/p?q=1"),
            (RequestLine, "GET /p?q=1 HTTP/1.1"),
            (RequestProtocol, "HTTP/1.1"),
            (RequestFilename, "/p"),
            (RequestBasename, "p"),
            (QueryString, "q=1"),
            (RequestBody, "body"),
            (ResponseBody, "resp"),
            (ResponseStatus, "200"),
            (RemoteAddr, "203.0.113.7"),
            (UniqueId, "uid"),
            (ReqbodyProcessor, "URLENCODED"),
            (MatchedVar, "1"),
        ] {
            let out = v.resolve(&[target(collection, None)]);
            assert_eq!(out.len(), 1, "{collection:?}");
            assert_eq!(
                String::from_utf8_lossy(&out[0].value),
                expected,
                "{collection:?}"
            );
        }
    }

    #[test]
    fn map_collections_resolve_with_qualified_names() {
        use Collection::*;
        let v = populated();
        assert_eq!(names(&v.resolve(&[target(ArgsGet, None)])), ["ARGS_GET:a"]);
        // ARGS spans both GET and POST.
        assert_eq!(
            names(&v.resolve(&[target(Args, None)])),
            ["ARGS:a", "ARGS:b"]
        );
        assert_eq!(
            names(&v.resolve(&[target(RequestHeaders, None)])),
            ["REQUEST_HEADERS:User-Agent"]
        );
        assert_eq!(
            names(&v.resolve(&[target(RequestCookies, None)])),
            ["REQUEST_COOKIES:sid"]
        );
        assert_eq!(
            names(&v.resolve(&[target(ResponseHeaders, None)])),
            ["RESPONSE_HEADERS:Server"]
        );
        assert_eq!(names(&v.resolve(&[target(Tx, None)])), ["TX:score"]);
        assert_eq!(names(&v.resolve(&[target(Files, None)])), ["FILES:upload"]);
        assert_eq!(
            names(&v.resolve(&[target(MultipartPartHeaders, None)])),
            ["MULTIPART_PART_HEADERS:Content-Type"]
        );
        assert_eq!(
            names(&v.resolve(&[target(MatchedVars, None)])),
            ["MATCHED_VARS:ARGS:a"]
        );
    }

    #[test]
    fn names_collections_inspect_member_names_as_values() {
        use Collection::*;
        let v = populated();
        for collection in [
            ArgsNames,
            ArgsGetNames,
            RequestHeadersNames,
            RequestCookiesNames,
            FilesNames,
        ] {
            let out = v.resolve(&[target(collection, None)]);
            assert!(!out.is_empty(), "{collection:?}");
            // The value equals the member name.
            let member = out[0].name.rsplit(':').next().unwrap();
            assert_eq!(
                String::from_utf8_lossy(&out[0].value),
                member,
                "{collection:?}"
            );
        }
    }

    #[test]
    fn combined_size_collections_report_a_number() {
        use Collection::*;
        let v = populated();
        let args = v.resolve(&[target(ArgsCombinedSize, None)]);
        assert_eq!(String::from_utf8_lossy(&args[0].value), "2"); // "1" + "2"
        let files = v.resolve(&[target(FilesCombinedSize, None)]);
        assert_eq!(String::from_utf8_lossy(&files[0].value), "8");
    }

    #[test]
    fn xml_resolves_elements_and_attributes() {
        use Collection::*;
        let v = populated();
        let elements = v.resolve(&[target(Xml, Some(CompiledSelector::XPath("/*".into())))]);
        assert_eq!(String::from_utf8_lossy(&elements[0].value), "text");
        let attrs = v.resolve(&[target(Xml, Some(CompiledSelector::XPath("//@*".into())))]);
        assert_eq!(String::from_utf8_lossy(&attrs[0].value), "val");
        // An XPath form that is neither yields nothing.
        assert!(v
            .resolve(&[target(Xml, Some(CompiledSelector::XPath("/root".into())))])
            .is_empty());
    }

    #[test]
    fn a_regex_selector_keeps_only_matching_members() {
        use Collection::*;
        let mut v = Variables::default();
        v.request_headers.push("X-Api-Key", &b"secret"[..]);
        v.request_headers.push("User-Agent", &b"curl"[..]);
        let re = CompiledSelector::Regex(regex::Regex::new("^X-").unwrap());
        let out = v.resolve(&[target(RequestHeaders, Some(re))]);
        assert_eq!(names(&out), ["REQUEST_HEADERS:X-Api-Key"]);
    }

    #[test]
    fn a_count_target_counts_members_and_set_scalars() {
        use Collection::*;
        let v = populated();
        let count = |c, sel| {
            let out = v.resolve(&[CompiledTarget {
                collection: c,
                selector: sel,
                exclusion: false,
                count: true,
            }]);
            String::from_utf8_lossy(&out[0].value).into_owned()
        };
        // Map: number of members.
        assert_eq!(count(Args, None), "2");
        // Scalar that is set counts as one.
        assert_eq!(count(RequestUri, None), "1");
        // A selector narrows the count.
        assert_eq!(
            count(
                RequestHeaders,
                Some(CompiledSelector::Name("user-agent".into()))
            ),
            "1"
        );
        // An unset scalar counts as zero.
        let empty = Variables::default();
        let out = empty.resolve(&[CompiledTarget {
            collection: RequestUri,
            selector: None,
            exclusion: false,
            count: true,
        }]);
        assert_eq!(String::from_utf8_lossy(&out[0].value), "0");
    }

    #[test]
    fn exclusion_by_name_and_regex_and_whole_collection() {
        use Collection::*;
        let mut v = Variables::default();
        v.args_get.push("keep", &b"1"[..]);
        v.args_get.push("__utmz", &b"2"[..]);
        // Name exclusion.
        let out = v.resolve(&[
            target(ArgsGet, None),
            CompiledTarget {
                collection: ArgsGet,
                selector: Some(CompiledSelector::Name("__utmz".into())),
                exclusion: true,
                count: false,
            },
        ]);
        assert_eq!(names(&out), ["ARGS_GET:keep"]);
        // Regex exclusion.
        let out = v.resolve(&[
            target(ArgsGet, None),
            CompiledTarget {
                collection: ArgsGet,
                selector: Some(CompiledSelector::Regex(regex::Regex::new("^__ut").unwrap())),
                exclusion: true,
                count: false,
            },
        ]);
        assert_eq!(names(&out), ["ARGS_GET:keep"]);
        // Whole-collection exclusion removes everything from that collection.
        let out = v.resolve(&[
            target(ArgsGet, None),
            CompiledTarget {
                collection: ArgsGet,
                selector: None,
                exclusion: true,
                count: false,
            },
        ]);
        assert!(out.is_empty());
        // An XPath exclusion never matches (XML has no exclusion semantics here).
        let out = v.resolve(&[
            target(ArgsGet, None),
            CompiledTarget {
                collection: ArgsGet,
                selector: Some(CompiledSelector::XPath("/*".into())),
                exclusion: true,
                count: false,
            },
        ]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn macro_context_reads_tx_and_scalars_and_reports_unknown() {
        let v = populated();
        assert_eq!(v.lookup("tx.score").as_deref(), Some(&b"5"[..]));
        assert_eq!(v.lookup("TX:score").as_deref(), Some(&b"5"[..]));
        assert_eq!(v.lookup("request_method").as_deref(), Some(&b"GET"[..]));
        assert_eq!(
            v.lookup("remote_addr").as_deref(),
            Some(&b"203.0.113.7"[..])
        );
        assert_eq!(v.lookup("matched_var_name"), Some(Cow::Borrowed(&b""[..])));
        assert!(v.lookup("nonexistent_variable").is_none());
    }
}
