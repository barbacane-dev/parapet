//! Transaction variables and how a [`Target`] resolves against them.
//!
//! SecLang collections are ordered and may hold duplicate names: a query
//! string can repeat a parameter, and a rule has to see every occurrence.
//! Resolution therefore yields `(name, value)` pairs in order rather than a
//! map lookup, which is also what `MATCHED_VAR_NAME` reports.

use std::borrow::Cow;

use crate::macros::MacroContext;
use crate::rule::{Collection, Selector, Target};

/// One resolved member of a collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    /// The fully qualified name, such as `ARGS:id`, as `MATCHED_VAR_NAME`
    /// reports it.
    pub name: String,
    /// The member's value.
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
    pub fn resolve(&self, targets: &[Target]) -> Vec<Value> {
        let mut out: Vec<Value> = Vec::new();
        let mut excluded: Vec<(Collection, Option<&Selector>)> = Vec::new();

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
                    if !value.name.starts_with(prefix) {
                        return false;
                    }
                    match selector {
                        None => true,
                        Some(Selector::Name(n)) => value
                            .name
                            .strip_prefix(prefix)
                            .and_then(|r| r.strip_prefix(':'))
                            .is_some_and(|member| member.eq_ignore_ascii_case(n)),
                        Some(Selector::Regex(pattern)) => value
                            .name
                            .strip_prefix(prefix)
                            .and_then(|r| r.strip_prefix(':'))
                            .is_some_and(|member| {
                                regex::Regex::new(pattern)
                                    .map(|re| re.is_match(member))
                                    .unwrap_or(false)
                            }),
                        // An XPath exclusion cannot be evaluated without an
                        // XML tree, and XML is never populated yet.
                        Some(Selector::XPath(_)) => false,
                    }
                })
            });
        }
        out
    }

    fn resolve_one(&self, target: &Target, out: &mut Vec<Value>) {
        use Collection::*;
        let prefix = collection_name(target.collection);

        // `&COLLECTION` inspects the member count, not the values.
        if target.count {
            let count = self.count_of(target);
            out.push(Value {
                name: prefix.to_string(),
                value: count.to_string().into_bytes(),
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

            ArgsCombinedSize => push_scalar(
                out,
                prefix,
                (self.args_get.combined_size() + self.args_post.combined_size())
                    .to_string()
                    .into_bytes(),
            ),
            FilesCombinedSize => push_scalar(
                out,
                prefix,
                self.files.combined_size().to_string().into_bytes(),
            ),

            RequestMethod => push_scalar(out, prefix, self.request_method.clone()),
            RequestUri => push_scalar(out, prefix, self.request_uri.clone()),
            RequestUriRaw => push_scalar(out, prefix, self.request_uri_raw.clone()),
            RequestLine => push_scalar(out, prefix, self.request_line.clone()),
            RequestProtocol => push_scalar(out, prefix, self.request_protocol.clone()),
            RequestFilename => push_scalar(out, prefix, self.request_filename.clone()),
            RequestBasename => push_scalar(out, prefix, self.request_basename.clone()),
            QueryString => push_scalar(out, prefix, self.query_string.clone()),
            RequestBody => push_scalar(out, prefix, self.request_body.clone()),
            ResponseBody => push_scalar(out, prefix, self.response_body.clone()),
            ResponseStatus => push_scalar(out, prefix, self.response_status.clone()),
            RemoteAddr => push_scalar(out, prefix, self.remote_addr.clone()),
            UniqueId => push_scalar(out, prefix, self.unique_id.clone()),
            ReqbodyProcessor => push_scalar(out, prefix, self.reqbody_processor.clone()),
            MatchedVar => push_scalar(out, prefix, self.matched_var.clone()),

            // Populated only by body parsers that do not exist yet. A request
            // in one of those formats sets REQBODY_ERROR instead of being
            // inspected against an empty collection.
            MultipartPartHeaders | Xml => {}
        }
    }

    /// How many members a `&COLLECTION` target sees.
    ///
    /// The selector matters: `&REQUEST_HEADERS:Transfer-Encoding` asks whether
    /// that one header is present, not how many headers there are. Counting
    /// the whole collection instead makes every presence check true, which
    /// silently fires the rules that test for a header being absent.
    fn count_of(&self, target: &Target) -> usize {
        let mut resolved = Vec::new();
        self.resolve_one(
            &Target {
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

fn push_scalar(out: &mut Vec<Value>, name: &str, value: Vec<u8>) {
    out.push(Value {
        name: name.to_string(),
        value,
    });
}

fn push_map(out: &mut Vec<Value>, prefix: &str, map: &Multimap, selector: Option<&Selector>) {
    for (name, value) in map.iter() {
        let keep = match selector {
            None => true,
            Some(Selector::Name(want)) => name.eq_ignore_ascii_case(want),
            Some(Selector::Regex(pattern)) => regex::Regex::new(pattern)
                .map(|re| re.is_match(name))
                .unwrap_or(false),
            Some(Selector::XPath(_)) => false,
        };
        if keep {
            out.push(Value {
                name: format!("{prefix}:{name}"),
                value: value.to_vec(),
            });
        }
    }
}

/// `*_NAMES` collections inspect the member names as values.
fn push_names<const N: usize>(out: &mut Vec<Value>, prefix: &str, maps: [&Multimap; N]) {
    for map in maps {
        for (name, _) in map.iter() {
            out.push(Value {
                name: format!("{prefix}:{name}"),
                value: name.as_bytes().to_vec(),
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
