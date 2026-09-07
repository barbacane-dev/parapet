//! `%{...}` macro expansion in operator operands and action arguments.
//!
//! CRS writes operands like `@ge %{tx.inbound_anomaly_score_threshold}` and
//! `!@within %{tx.allowed_methods}`, so an operand is a template resolved
//! against transaction state at evaluation time, not a constant.

use std::borrow::Cow;

/// Supplies values for `%{...}` references.
pub trait MacroContext {
    /// Look up a macro by name, case-insensitively as SecLang is.
    ///
    /// An unknown name expands to nothing, matching SecLang, where an unset
    /// variable is empty rather than an error.
    fn lookup(&self, name: &str) -> Option<Cow<'_, [u8]>>;
}

/// A [`MacroContext`] with nothing in it. Every lookup expands to empty.
pub struct EmptyContext;

impl MacroContext for EmptyContext {
    fn lookup(&self, _name: &str) -> Option<Cow<'_, [u8]>> {
        None
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Part {
    Literal(Vec<u8>),
    Macro(String),
}

/// An operand or argument that may contain `%{...}` references.
#[derive(Debug, Clone, PartialEq)]
pub struct Template {
    parts: Vec<Part>,
}

impl Template {
    /// Parse a template. An unterminated `%{` is treated as literal text,
    /// since refusing would reject rules other engines accept.
    pub fn parse(source: &str) -> Self {
        let bytes = source.as_bytes();
        let mut parts = Vec::new();
        let mut literal = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && bytes.get(i + 1) == Some(&b'{') {
                if let Some(end) = bytes[i + 2..].iter().position(|b| *b == b'}') {
                    let name = &source[i + 2..i + 2 + end];
                    if !literal.is_empty() {
                        parts.push(Part::Literal(std::mem::take(&mut literal)));
                    }
                    parts.push(Part::Macro(name.to_string()));
                    i += 2 + end + 1;
                    continue;
                }
            }
            literal.push(bytes[i]);
            i += 1;
        }
        if !literal.is_empty() {
            parts.push(Part::Literal(literal));
        }
        Template { parts }
    }

    /// Whether the template is a constant, so expansion can be skipped.
    pub fn is_literal(&self) -> bool {
        !self.parts.iter().any(|p| matches!(p, Part::Macro(_)))
    }

    /// Expand against a context.
    pub fn expand(&self, ctx: &dyn MacroContext) -> Cow<'_, [u8]> {
        if let [Part::Literal(only)] = self.parts.as_slice() {
            return Cow::Borrowed(only);
        }
        if self.parts.is_empty() {
            return Cow::Borrowed(&[]);
        }
        let mut out = Vec::new();
        for part in &self.parts {
            match part {
                Part::Literal(bytes) => out.extend_from_slice(bytes),
                Part::Macro(name) => {
                    if let Some(value) = ctx.lookup(name) {
                        out.extend_from_slice(&value);
                    }
                }
            }
        }
        Cow::Owned(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Map(HashMap<String, Vec<u8>>);

    impl MacroContext for Map {
        fn lookup(&self, name: &str) -> Option<Cow<'_, [u8]>> {
            self.0
                .get(&name.to_ascii_lowercase())
                .map(|v| Cow::Borrowed(v.as_slice()))
        }
    }

    fn ctx() -> Map {
        let mut m = HashMap::new();
        m.insert("tx.threshold".to_string(), b"5".to_vec());
        m.insert("tx.allowed_methods".to_string(), b"GET HEAD POST".to_vec());
        Map(m)
    }

    #[test]
    fn a_constant_template_is_literal_and_borrows() {
        let t = Template::parse("GET");
        assert!(t.is_literal());
        assert!(matches!(t.expand(&EmptyContext), Cow::Borrowed(_)));
    }

    #[test]
    fn expands_a_single_macro() {
        let t = Template::parse("%{tx.threshold}");
        assert!(!t.is_literal());
        assert_eq!(t.expand(&ctx()).as_ref(), b"5");
    }

    #[test]
    fn expands_mixed_literal_and_macro() {
        let t = Template::parse("score=%{tx.threshold}!");
        assert_eq!(t.expand(&ctx()).as_ref(), b"score=5!");
    }

    #[test]
    fn macro_names_are_case_insensitive() {
        let t = Template::parse("%{TX.Threshold}");
        assert_eq!(t.expand(&ctx()).as_ref(), b"5");
    }

    #[test]
    fn an_unknown_macro_expands_to_nothing() {
        let t = Template::parse("a%{tx.missing}b");
        assert_eq!(t.expand(&ctx()).as_ref(), b"ab");
    }

    #[test]
    fn an_unterminated_macro_stays_literal() {
        let t = Template::parse("100%{ of it");
        assert!(t.is_literal());
        assert_eq!(t.expand(&ctx()).as_ref(), b"100%{ of it");
    }

    #[test]
    fn an_empty_template_expands_to_empty() {
        assert_eq!(Template::parse("").expand(&ctx()).as_ref(), b"");
    }
}
