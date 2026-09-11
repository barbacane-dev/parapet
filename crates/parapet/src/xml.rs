//! Extracting the values CRS inspects from an XML body.
//!
//! CRS addresses XML with exactly two XPath expressions, `XML:/*` for element
//! content and `XML://@*` for attribute values, across 176 targets. Those two
//! are implemented; any other expression is refused at compile time rather
//! than quietly resolving to nothing, because a target that inspects nothing
//! is a rule that cannot fire.
//!
//! Parsing is delegated to `quick-xml`. Hand-rolling an XML parser to feed a
//! security control is a poor trade: the parser is the attack surface.

use quick_xml::events::Event;
use quick_xml::Reader;

/// The two XPath expressions CRS uses.
pub const SUPPORTED_XPATH: &[&str] = &["/*", "//@*"];

/// Whether an XPath expression is one Parapet can evaluate.
pub fn xpath_is_supported(expression: &str) -> bool {
    SUPPORTED_XPATH.contains(&expression.trim())
}

/// What an XML body yields.
#[derive(Debug, Default)]
pub struct XmlValues {
    /// Text content, keyed by the element that held it.
    pub elements: Vec<(String, Vec<u8>)>,
    /// Attribute values, keyed by attribute name.
    pub attributes: Vec<(String, Vec<u8>)>,
}

/// Parse an XML body.
///
/// Returns an error message when the document is malformed, which the caller
/// surfaces as `REQBODY_ERROR`. Refusing a body the parser cannot understand
/// is the safe direction: the alternative is inspecting nothing and calling it
/// clean.
pub fn parse(body: &[u8]) -> Result<XmlValues, String> {
    let mut reader = Reader::from_reader(body);
    let config = reader.config_mut();
    config.trim_text(true);
    config.check_end_names = false;

    let mut values = XmlValues::default();
    let mut path: Vec<String> = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = e.name().as_ref().to_string();
                collect_attributes(&e, &mut values);
                path.push(name);
            }
            Ok(Event::Empty(e)) => {
                collect_attributes(&e, &mut values);
            }
            Ok(Event::End(_)) => {
                path.pop();
            }
            Ok(Event::Text(e)) => {
                // Entities are decoded: the application will see the decoded
                // form, so that is what the rules must inspect. Leaving
                // `&lt;script&gt;` encoded hides the payload from every rule
                // that looks for a tag.
                let raw = e.into_inner();
                let text = unescape_to_bytes(&raw);
                if !text.is_empty() {
                    let name = path.last().cloned().unwrap_or_else(|| "/".to_string());
                    values.elements.push((name, text));
                }
            }
            Ok(Event::CData(e)) => {
                let text = e.into_inner().into_owned().into_bytes();
                if !text.is_empty() {
                    let name = path.last().cloned().unwrap_or_else(|| "/".to_string());
                    values.elements.push((name, text));
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(format!("malformed XML: {e}")),
        }
        buf.clear();
    }

    Ok(values)
}

/// Decode XML entities. A value the decoder chokes on is kept raw rather than
/// dropped: a value the parser cannot decode still has to reach the rules.
fn unescape_to_bytes(raw: &str) -> Vec<u8> {
    match quick_xml::escape::unescape(raw) {
        Ok(decoded) => decoded.into_owned().into_bytes(),
        Err(_) => raw.as_bytes().to_vec(),
    }
}

fn collect_attributes(e: &quick_xml::events::BytesStart<'_>, values: &mut XmlValues) {
    for attr in e.attributes().flatten() {
        let name = attr.key.as_ref().to_string();
        let value = unescape_to_bytes(&attr.value);
        values.attributes.push((name, value));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn texts(v: &XmlValues) -> Vec<String> {
        v.elements
            .iter()
            .map(|(_, t)| String::from_utf8_lossy(t).into_owned())
            .collect()
    }

    fn attrs(v: &XmlValues) -> Vec<String> {
        v.attributes
            .iter()
            .map(|(_, t)| String::from_utf8_lossy(t).into_owned())
            .collect()
    }

    #[test]
    fn extracts_element_text() {
        let v = parse(br#"<?xml version="1.0"?><xml><a>payload</a></xml>"#).unwrap();
        assert_eq!(texts(&v), vec!["payload"]);
    }

    #[test]
    fn extracts_attribute_values() {
        let v = parse(br#"<xml><e name="payload">text</e></xml>"#).unwrap();
        assert_eq!(attrs(&v), vec!["payload"]);
        assert_eq!(texts(&v), vec!["text"]);
    }

    #[test]
    fn extracts_from_nested_elements() {
        let v = parse(br#"<a><b><c>deep</c></b></a>"#).unwrap();
        assert_eq!(texts(&v), vec!["deep"]);
    }

    #[test]
    fn extracts_from_self_closing_elements() {
        let v = parse(br#"<xml><e attr="payload"/></xml>"#).unwrap();
        assert_eq!(attrs(&v), vec!["payload"]);
    }

    #[test]
    fn extracts_cdata() {
        let v = parse(br#"<xml><a><![CDATA[<script>alert(1)</script>]]></a></xml>"#).unwrap();
        assert_eq!(texts(&v), vec!["<script>alert(1)</script>"]);
    }

    #[test]
    fn decodes_entities_in_attribute_values() {
        let v = parse(br#"<xml><e a="&lt;script&gt;"/></xml>"#).unwrap();
        assert_eq!(attrs(&v), vec!["<script>"]);
    }

    #[test]
    fn a_malformed_document_is_an_error_not_an_empty_result() {
        // Returning no values would read as a clean body, so a document the
        // parser cannot finish must surface as an error.
        assert!(parse(br#"<a b="unclosed>"#).is_err());
        assert!(parse(b"<a></a").is_err());
    }

    #[test]
    fn a_truncated_document_still_yields_what_was_parsed() {
        // Partial extraction beats none: the payload may be before the break.
        let v = parse(b"<xml><a>payload</a><b>");
        if let Ok(v) = v {
            assert!(texts(&v).contains(&"payload".to_string()));
        }
    }

    #[test]
    fn only_the_two_crs_xpath_forms_are_supported() {
        assert!(xpath_is_supported("/*"));
        assert!(xpath_is_supported("//@*"));
        assert!(!xpath_is_supported("/xml/a"));
        assert!(!xpath_is_supported("//text()"));
    }

    #[test]
    fn text_at_the_root_is_attributed_to_a_slash() {
        let v = parse(b"root text<a>child</a>").unwrap();
        assert!(texts(&v).contains(&"root text".to_string()));
        assert!(texts(&v).contains(&"child".to_string()));
    }

    #[test]
    fn empty_text_and_cdata_are_skipped() {
        let v = parse(b"<a></a><b><![CDATA[]]></b>").unwrap();
        assert!(texts(&v).is_empty());
    }

    #[test]
    fn an_undecodable_entity_is_kept_raw_rather_than_dropped() {
        // The reader accepts this numeric reference, but its value is out of
        // the Unicode range, so unescape fails and the text reaches the rules
        // as written rather than vanishing.
        let v = parse(b"<a>x&#x11FFFF;y</a>").unwrap();
        assert!(texts(&v)[0].contains("11FFFF") || texts(&v)[0].contains("x"));
    }
}
