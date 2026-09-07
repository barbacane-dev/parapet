//! Flattening a JSON body into `ARGS`.
//!
//! SecLang has no JSON collection: the JSON body processor flattens the
//! document into the argument collection, so the same rules that inspect form
//! fields inspect JSON fields. Keys become argument names and scalars become
//! values, which is what lets a rule written for `ARGS` catch a payload posted
//! as JSON.

/// Flatten a JSON document into `(name, value)` argument pairs.
///
/// Names follow the `json.path.to.field` convention, with array indices as
/// path segments. Returns an error for a malformed document, which the caller
/// surfaces as `REQBODY_ERROR`: a body the parser cannot read must not be
/// reported as clean.
///
/// Object keys come out sorted rather than in document order. Every field is
/// inspected either way, so this only affects which one `MATCHED_VAR` names
/// when several match.
pub fn flatten(body: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("malformed JSON: {e}"))?;
    let mut out = Vec::new();
    walk("json", &value, &mut out);
    Ok(out)
}

fn walk(path: &str, value: &serde_json::Value, out: &mut Vec<(String, Vec<u8>)>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                walk(&format!("{path}.{key}"), child, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                walk(&format!("{path}.{i}"), child, out);
            }
        }
        serde_json::Value::String(s) => out.push((path.to_string(), s.as_bytes().to_vec())),
        serde_json::Value::Number(n) => out.push((path.to_string(), n.to_string().into_bytes())),
        serde_json::Value::Bool(b) => out.push((path.to_string(), b.to_string().into_bytes())),
        // A null carries no value to inspect, but the key still exists and
        // ARGS_NAMES rules look at names.
        serde_json::Value::Null => out.push((path.to_string(), Vec::new())),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn names(pairs: &[(String, Vec<u8>)]) -> Vec<&str> {
        pairs.iter().map(|(n, _)| n.as_str()).collect()
    }

    fn values(pairs: &[(String, Vec<u8>)]) -> Vec<String> {
        pairs
            .iter()
            .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
            .collect()
    }

    #[test]
    fn flattens_a_flat_object() {
        let out = flatten(br#"{"test": "payload"}"#).unwrap();
        assert_eq!(names(&out), vec!["json.test"]);
        assert_eq!(values(&out), vec!["payload"]);
    }

    #[test]
    fn a_key_is_inspectable_as_a_name() {
        // CRS rules target ARGS_NAMES too, so a payload hidden in a key must
        // still reach them.
        let out = flatten(br#"{"com.opensymphony.xwork2": "test"}"#).unwrap();
        assert_eq!(names(&out), vec!["json.com.opensymphony.xwork2"]);
    }

    #[test]
    fn flattens_nested_objects_and_arrays() {
        let out = flatten(br#"{"a": {"b": ["x", "y"]}}"#).unwrap();
        assert_eq!(names(&out), vec!["json.a.b.0", "json.a.b.1"]);
        assert_eq!(values(&out), vec!["x", "y"]);
    }

    #[test]
    fn carries_scalars_of_every_type() {
        // Object keys are sorted, not in document order.
        let out = flatten(br#"{"n": 42, "b": true, "z": null}"#).unwrap();
        assert_eq!(names(&out), vec!["json.b", "json.n", "json.z"]);
        assert_eq!(values(&out), vec!["true", "42", ""]);
    }

    #[test]
    fn array_order_is_preserved() {
        // Arrays are ordered by definition, and the index is part of the name.
        let out = flatten(br#"{"a": ["first", "second", "third"]}"#).unwrap();
        assert_eq!(values(&out), vec!["first", "second", "third"]);
    }

    #[test]
    fn a_bare_scalar_document_is_still_inspectable() {
        let out = flatten(br#""payload""#).unwrap();
        assert_eq!(values(&out), vec!["payload"]);
    }

    #[test]
    fn a_malformed_document_is_an_error_not_an_empty_result() {
        assert!(flatten(b"{not json").is_err());
        assert!(flatten(b"").is_err());
    }
}
