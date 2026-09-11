//! Transformations applied to a target before an operator sees it.
//!
//! These matter more than their size suggests. A rule that inspects raw input
//! is trivially evaded by encoding the payload, so CRS stacks decoders
//! (`t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode`) ahead of nearly every
//! operator. A decoder that is too conservative leaves a bypass; one that is
//! too eager creates false positives on legitimate traffic.
//!
//! Everything here works on bytes, not `str`. Input is attacker-controlled and
//! frequently not valid UTF-8, and several of these transformations exist
//! precisely to normalise malformed encodings.

use std::borrow::Cow;

use crate::action::Transformation;

impl Transformation {
    /// Apply the transformation.
    ///
    /// Returns a borrow when the transformation leaves the input unchanged, so
    /// a chain of no-ops copies nothing.
    pub fn apply<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        use Transformation::*;
        match self {
            None => Cow::Borrowed(input),
            Base64Decode => Cow::Owned(base64_decode(input)),
            CmdLine => Cow::Owned(cmd_line(input)),
            CompressWhitespace => compress_whitespace(input),
            CssDecode => Cow::Owned(css_decode(input)),
            EscapeSeqDecode => Cow::Owned(escape_seq_decode(input)),
            HexEncode => Cow::Owned(hex_encode(input)),
            HtmlEntityDecode => Cow::Owned(html_entity_decode(input)),
            JsDecode => Cow::Owned(js_decode(input)),
            Length => Cow::Owned(input.len().to_string().into_bytes()),
            Lowercase => lowercase(input),
            NormalizePath => normalize_path(input),
            NormalizePathWin => {
                let slashed: Vec<u8> = input
                    .iter()
                    .map(|b| if *b == b'\\' { b'/' } else { *b })
                    .collect();
                Cow::Owned(normalize_path(&slashed).into_owned())
            }
            RemoveCommentsChar => Cow::Owned(remove_comments_char(input)),
            RemoveNulls => remove_bytes(input, |b| b == 0),
            RemoveWhitespace => remove_bytes(input, is_ascii_space),
            ReplaceComments => Cow::Owned(replace_comments(input)),
            Sha1 => {
                use sha1::Digest;
                Cow::Owned(sha1::Sha1::digest(input).to_vec())
            }
            UrlDecodeUni => Cow::Owned(url_decode_uni(input)),
            Utf8ToUnicode => utf8_to_unicode(input),
        }
    }
}

/// The whitespace bytes these transformations recognise: HT, LF, VT, FF, CR
/// and space.
///
/// Deliberately ASCII-only. NBSP (0xa0) and the Unicode space separators are
/// not folded here, which is a known divergence to settle against the CRS
/// regression suite rather than by guesswork.
fn is_ascii_space(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ')
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => Option::None,
    }
}

fn lowercase(input: &[u8]) -> Cow<'_, [u8]> {
    if input.iter().any(u8::is_ascii_uppercase) {
        Cow::Owned(input.to_ascii_lowercase())
    } else {
        Cow::Borrowed(input)
    }
}

fn remove_bytes(input: &[u8], drop: fn(u8) -> bool) -> Cow<'_, [u8]> {
    if input.iter().copied().any(drop) {
        Cow::Owned(input.iter().copied().filter(|b| !drop(*b)).collect())
    } else {
        Cow::Borrowed(input)
    }
}

fn hex_encode(input: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(input.len() * 2);
    for b in input {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0f) as usize]);
    }
    out
}

/// Fold whitespace runs to a single space.
fn compress_whitespace(input: &[u8]) -> Cow<'_, [u8]> {
    let needs = input
        .windows(2)
        .any(|w| is_ascii_space(w[0]) && is_ascii_space(w[1]))
        || input.iter().any(|b| is_ascii_space(*b) && *b != b' ');
    if !needs {
        return Cow::Borrowed(input);
    }
    let mut out = Vec::with_capacity(input.len());
    let mut in_space = false;
    for b in input.iter().copied() {
        if is_ascii_space(b) {
            if !in_space {
                out.push(b' ');
                in_space = true;
            }
        } else {
            out.push(b);
            in_space = false;
        }
    }
    Cow::Owned(out)
}

/// ModSecurity's `cmdLine`, which normalises shell obfuscation.
///
/// The documented steps, in order: delete backslashes, double quotes, single
/// quotes and carets; delete a space before `/` or `(`; replace commas and
/// semicolons with a space; collapse whitespace runs to one space; lowercase.
fn cmd_line(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut in_space = false;
    for b in input.iter().copied() {
        match b {
            b'"' | b'\'' | b'\\' | b'^' => {}
            b' ' | b',' | b';' | b'\t' | b'\r' | b'\n' => {
                if !in_space {
                    out.push(b' ');
                    in_space = true;
                }
            }
            b'/' | b'(' => {
                if in_space {
                    out.pop();
                }
                in_space = false;
                out.push(b);
            }
            other => {
                out.push(other.to_ascii_lowercase());
                in_space = false;
            }
        }
    }
    out
}

/// Resolve `.` and `..` segments and collapse repeated slashes.
fn normalize_path(input: &[u8]) -> Cow<'_, [u8]> {
    if input.is_empty() {
        return Cow::Borrowed(input);
    }
    let absolute = input[0] == b'/';
    let trailing_slash = input.len() > 1 && input[input.len() - 1] == b'/';

    let mut stack: Vec<&[u8]> = Vec::new();
    for segment in input.split(|b| *b == b'/') {
        match segment {
            b"" | b"." => {}
            b".." => {
                match stack.last() {
                    Some(last) if *last != b".." => {
                        stack.pop();
                    }
                    // A `..` above the root is dropped; above a relative path
                    // it is significant and kept.
                    _ => {
                        if !absolute {
                            stack.push(b"..");
                        }
                    }
                }
            }
            other => stack.push(other),
        }
    }

    let mut out = Vec::with_capacity(input.len());
    if absolute {
        out.push(b'/');
    }
    for (i, segment) in stack.iter().enumerate() {
        if i > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(segment);
    }
    if trailing_slash && !out.is_empty() && out != b"/" {
        out.push(b'/');
    }
    if out == input {
        Cow::Borrowed(input)
    } else {
        Cow::Owned(out)
    }
}

/// Strip the character sequences that introduce or end comments, without
/// removing the commented content.
fn remove_comments_char(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let rest = &input[i..];
        // Longest delimiters first: `-->` must be matched before `--`, and
        // `<!--` before it too, or the tail of the longer delimiter survives.
        if rest.starts_with(b"<!--") {
            i += 4;
        } else if rest.starts_with(b"-->") {
            i += 3;
        } else if rest.starts_with(b"/*") || rest.starts_with(b"*/") || rest.starts_with(b"--") {
            i += 2;
        } else if rest[0] == b'#' {
            i += 1;
        } else {
            out.push(rest[0]);
            i += 1;
        }
    }
    out
}

/// Replace each C-style comment with a single space. An unterminated comment
/// consumes the rest of the input, which is what stops `/*` from hiding a
/// payload from the operator.
fn replace_comments(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i..].starts_with(b"/*") {
            out.push(b' ');
            i += 2;
            while i < input.len() && !input[i..].starts_with(b"*/") {
                i += 1;
            }
            i = (i + 2).min(input.len());
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    out
}

/// Decode the HTML entities ModSecurity recognises: `&#DD;`, `&#xHH;` and the
/// named entities `lt`, `gt`, `amp`, `quot` and `nbsp`.
///
/// The trailing semicolon is optional, matching browser leniency, which is the
/// behaviour an attacker relies on.
fn html_entity_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'&' {
            out.push(input[i]);
            i += 1;
            continue;
        }
        let rest = &input[i + 1..];
        if let Some(after_hash) = rest.strip_prefix(b"#") {
            // Hex form: &#xHH
            let (is_hex, digits) = match after_hash.first() {
                Some(b'x') | Some(b'X') => (true, &after_hash[1..]),
                _ => (false, after_hash),
            };
            let radix_len = digits
                .iter()
                .take_while(|b| {
                    if is_hex {
                        b.is_ascii_hexdigit()
                    } else {
                        b.is_ascii_digit()
                    }
                })
                .count();
            if radix_len > 0 {
                let mut value: u32 = 0;
                for b in &digits[..radix_len] {
                    let d = if is_hex {
                        hex_nibble(*b).unwrap_or(0) as u32
                    } else {
                        (b - b'0') as u32
                    };
                    value = value
                        .saturating_mul(if is_hex { 16 } else { 10 })
                        .saturating_add(d);
                }
                out.push((value & 0xff) as u8);
                i += 1 + 1 + usize::from(is_hex) + radix_len;
                if input.get(i) == Some(&b';') {
                    i += 1;
                }
                continue;
            }
        } else {
            const NAMED: &[(&[u8], u8)] = &[
                (b"lt", b'<'),
                (b"gt", b'>'),
                (b"amp", b'&'),
                (b"quot", b'"'),
                (b"nbsp", 0xa0),
            ];
            let mut matched = false;
            for (name, byte) in NAMED {
                if rest.len() >= name.len() && rest[..name.len()].eq_ignore_ascii_case(name) {
                    out.push(*byte);
                    i += 1 + name.len();
                    if input.get(i) == Some(&b';') {
                        i += 1;
                    }
                    matched = true;
                    break;
                }
            }
            if matched {
                continue;
            }
        }
        out.push(b'&');
        i += 1;
    }
    out
}

/// Full-width ASCII (U+FF01 through U+FF5E) folds to its ASCII equivalent by
/// subtracting 0xFEE0. Applied to `%uXXXX` and `\uXXXX` escapes.
///
/// ModSecurity additionally consults a ~370-entry best-fit table (codepage
/// 20127 of `unicode.mapping`) covering typographic quotes and similar folds.
/// That table is not implemented here: unmapped code points fall back to the
/// low byte, which is ModSecurity's own fallback. This is a known divergence,
/// to be closed or dismissed by the CRS regression suite rather than assumed
/// either way.
fn fold_unicode_code_point(code: u32) -> u8 {
    if (0xff01..=0xff5e).contains(&code) {
        return (code - 0xfee0) as u8;
    }
    (code & 0xff) as u8
}

/// Percent-decoding including IIS-style `%uXXXX`, and `+` as space.
fn url_decode_uni(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                let rest = &input[i + 1..];
                match rest.first() {
                    Some(b'u') | Some(b'U') if rest.len() >= 5 => {
                        let h: Option<Vec<u8>> =
                            rest[1..5].iter().map(|b| hex_nibble(*b)).collect();
                        match h {
                            Some(n) => {
                                let code = (n[0] as u32) << 12
                                    | (n[1] as u32) << 8
                                    | (n[2] as u32) << 4
                                    | n[3] as u32;
                                out.push(fold_unicode_code_point(code));
                                i += 6;
                            }
                            // An invalid escape is left verbatim, as a decoder
                            // that swallowed it would hide the payload.
                            Option::None => {
                                out.push(b'%');
                                i += 1;
                            }
                        }
                    }
                    _ if rest.len() >= 2 => match (hex_nibble(rest[0]), hex_nibble(rest[1])) {
                        (Some(hi), Some(lo)) => {
                            out.push(hi << 4 | lo);
                            i += 3;
                        }
                        _ => {
                            out.push(b'%');
                            i += 1;
                        }
                    },
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    out
}

/// Rewrite non-ASCII UTF-8 sequences as `%uXXXX`.
fn utf8_to_unicode(input: &[u8]) -> Cow<'_, [u8]> {
    if input.is_ascii() {
        return Cow::Borrowed(input);
    }
    let mut out = Vec::with_capacity(input.len() * 2);
    let mut rest = input;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                push_runes(&mut out, s);
                break;
            }
            Err(e) => {
                let (good, bad) = rest.split_at(e.valid_up_to());
                // `good` is valid UTF-8 by construction.
                if let Ok(s) = std::str::from_utf8(good) {
                    push_runes(&mut out, s);
                }
                let skip = e.error_len().unwrap_or(bad.len()).max(1);
                // Invalid bytes are emitted unchanged: this transformation
                // re-encodes what it understands and does not sanitise.
                out.extend_from_slice(&bad[..skip.min(bad.len())]);
                rest = &bad[skip.min(bad.len())..];
            }
        }
    }
    Cow::Owned(out)
}

fn push_runes(out: &mut Vec<u8>, s: &str) {
    for ch in s.chars() {
        if ch.is_ascii() {
            out.push(ch as u8);
        } else {
            out.extend_from_slice(format!("%u{:04x}", ch as u32).as_bytes());
        }
    }
}

/// Decode `\uHHHH`, `\u{H...H}`, `\xHH`, octal and single-character C escapes.
fn js_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'\\' || i + 1 >= input.len() {
            out.push(input[i]);
            i += 1;
            continue;
        }
        let rest = &input[i + 1..];
        match rest[0] {
            b'u' if rest.len() >= 2 && rest[1] == b'{' => {
                let digits: Vec<u8> = rest[2..]
                    .iter()
                    .take_while(|b| b.is_ascii_hexdigit())
                    .copied()
                    .collect();
                let closes = rest.get(2 + digits.len()) == Some(&b'}');
                if !digits.is_empty() && digits.len() <= 6 && closes {
                    let mut code: u32 = 0;
                    for b in &digits {
                        code = code << 4 | hex_nibble(*b).unwrap_or(0) as u32;
                    }
                    out.push(fold_unicode_code_point(code));
                    i += 1 + 2 + digits.len() + 1;
                } else {
                    out.push(b'u');
                    i += 2;
                }
            }
            b'u' if rest.len() >= 5 && rest[1..5].iter().all(u8::is_ascii_hexdigit) => {
                let mut code: u32 = 0;
                for b in &rest[1..5] {
                    code = code << 4 | hex_nibble(*b).unwrap_or(0) as u32;
                }
                out.push(fold_unicode_code_point(code));
                i += 6;
            }
            b'x' if rest.len() >= 3
                && rest[1].is_ascii_hexdigit()
                && rest[2].is_ascii_hexdigit() =>
            {
                out.push(hex_nibble(rest[1]).unwrap_or(0) << 4 | hex_nibble(rest[2]).unwrap_or(0));
                i += 4;
            }
            b'0'..=b'7' => {
                let digits: Vec<u8> = rest
                    .iter()
                    .take_while(|b| (b'0'..=b'7').contains(b))
                    .take(3)
                    .copied()
                    .collect();
                let mut value: u32 = 0;
                for b in &digits {
                    value = value * 8 + (b - b'0') as u32;
                }
                out.push((value & 0xff) as u8);
                i += 1 + digits.len();
            }
            other => {
                out.push(single_char_escape(other));
                i += 2;
            }
        }
    }
    out
}

/// Decode `\a \b \f \n \r \t \v`, `\xHH` and octal escapes.
fn escape_seq_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'\\' || i + 1 >= input.len() {
            out.push(input[i]);
            i += 1;
            continue;
        }
        let rest = &input[i + 1..];
        match rest[0] {
            b'x' if rest.len() >= 3
                && rest[1].is_ascii_hexdigit()
                && rest[2].is_ascii_hexdigit() =>
            {
                out.push(hex_nibble(rest[1]).unwrap_or(0) << 4 | hex_nibble(rest[2]).unwrap_or(0));
                i += 4;
            }
            b'0'..=b'7' => {
                let digits: Vec<u8> = rest
                    .iter()
                    .take_while(|b| (b'0'..=b'7').contains(b))
                    .take(3)
                    .copied()
                    .collect();
                let mut value: u32 = 0;
                for b in &digits {
                    value = value * 8 + (b - b'0') as u32;
                }
                out.push((value & 0xff) as u8);
                i += 1 + digits.len();
            }
            other => {
                out.push(single_char_escape(other));
                i += 2;
            }
        }
    }
    out
}

/// `\n` and friends. An escape of anything else yields that character, which
/// is how `\S\E\L\E\C\T` collapses to `SELECT`.
fn single_char_escape(c: u8) -> u8 {
    match c {
        b'a' => 0x07,
        b'b' => 0x08,
        b'f' => 0x0c,
        b'n' => b'\n',
        b'r' => b'\r',
        b't' => b'\t',
        b'v' => 0x0b,
        other => other,
    }
}

/// Decode CSS escapes.
///
/// A backslash followed by one to six hex digits resolves to a code point,
/// which is then encoded as UTF-8. Truncating to the low byte instead would
/// produce invalid UTF-8 for any non-ASCII target, and would mis-decode any
/// escape of three or more digits whose value does not fit in the last two.
/// A zero code point is invalid per the CSS syntax spec and resolves to
/// U+FFFD, as do surrogates and out-of-range values.
fn css_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'\\' {
            out.push(input[i]);
            i += 1;
            continue;
        }
        // A trailing backslash with nothing after it is dropped.
        if i + 1 >= input.len() {
            break;
        }
        let rest = &input[i + 1..];
        let digits: Vec<u8> = rest
            .iter()
            .take_while(|b| b.is_ascii_hexdigit())
            .take(6)
            .copied()
            .collect();
        if digits.is_empty() {
            // A backslash before a newline is a line continuation and vanishes.
            if rest[0] == b'\n' {
                i += 2;
            } else {
                out.push(rest[0]);
                i += 2;
            }
            continue;
        }
        let mut code: u32 = 0;
        for b in &digits {
            code = code << 4 | hex_nibble(*b).unwrap_or(0) as u32;
        }
        // Full-width ASCII folds to plain ASCII before encoding.
        if (0xff01..=0xff5e).contains(&code) {
            code -= 0xfee0;
        }
        let ch = if code == 0 {
            char::REPLACEMENT_CHARACTER
        } else {
            char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER)
        };
        let mut buf = [0u8; 4];
        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        i += 1 + digits.len();
        // A single whitespace byte terminates the escape and is consumed.
        if input.get(i).is_some_and(|b| is_ascii_space(*b)) {
            i += 1;
        }
    }
    out
}

/// Base64 decoding that returns the partial result up to the first invalid
/// byte.
///
/// Padding is optional, CR and LF are ignored, and any other byte outside the
/// alphabet ends the decode. Skipping arbitrary invalid bytes instead would
/// make the transformation decode strings that no real decoder accepts, which
/// manufactures matches on traffic that was never base64 at all. `t:base64Decode`
/// is the strict form; the lenient variant is a separate SecLang transformation
/// (`base64DecodeExt`), which CRS does not use.
fn base64_decode(input: &[u8]) -> Vec<u8> {
    fn value(b: u8) -> Option<u8> {
        Some(match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Option::None,
        })
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4 + 3);
    let mut group = [0u8; 4];
    let mut n = 0;
    for b in input.iter().copied() {
        if b == b'\r' || b == b'\n' {
            continue;
        }
        let Some(v) = value(b) else {
            // Padding or any other byte outside the alphabet ends the decode.
            break;
        };
        group[n] = v;
        n += 1;
        if n == 4 {
            out.push(group[0] << 2 | group[1] >> 4);
            out.push(group[1] << 4 | group[2] >> 2);
            out.push(group[2] << 6 | group[3]);
            n = 0;
        }
    }
    match n {
        2 => out.push(group[0] << 2 | group[1] >> 4),
        3 => {
            out.push(group[0] << 2 | group[1] >> 4);
            out.push(group[1] << 4 | group[2] >> 2);
        }
        _ => {}
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::action::Transformation as T;

    /// Apply a transformation to a string and read the result back as a string.
    fn t(kind: T, input: &str) -> String {
        String::from_utf8_lossy(&kind.apply(input.as_bytes())).into_owned()
    }

    #[test]
    fn none_borrows_and_changes_nothing() {
        let input = b"unchanged";
        assert!(matches!(T::None.apply(input), Cow::Borrowed(_)));
    }

    #[test]
    fn unchanged_input_is_not_copied() {
        // A chain of no-ops should not allocate.
        assert!(matches!(
            T::Lowercase.apply(b"already lower"),
            Cow::Borrowed(_)
        ));
        assert!(matches!(
            T::RemoveNulls.apply(b"no nulls"),
            Cow::Borrowed(_)
        ));
        assert!(matches!(
            T::Utf8ToUnicode.apply(b"pure ascii"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn lowercase_is_ascii_only() {
        assert_eq!(t(T::Lowercase, "SeLeCt"), "select");
    }

    #[test]
    fn length_reports_bytes_not_characters() {
        assert_eq!(t(T::Length, "abc"), "3");
        assert_eq!(t(T::Length, ""), "0");
        // Three bytes, one character.
        assert_eq!(t(T::Length, "\u{20ac}"), "3");
    }

    #[test]
    fn hex_encode_is_lowercase() {
        assert_eq!(t(T::HexEncode, "AB\n"), "41420a");
    }

    #[test]
    fn sha1_matches_the_known_vector() {
        let out = T::Sha1.apply(b"abc");
        assert_eq!(
            hex_encode(&out),
            b"a9993e364706816aba3e25717850c26c9cd0d89d".to_vec()
        );
    }

    #[test]
    fn remove_nulls_defeats_null_byte_splitting() {
        assert_eq!(t(T::RemoveNulls, "sel\0ect"), "select");
    }

    #[test]
    fn remove_whitespace_strips_every_ascii_space_byte() {
        assert_eq!(t(T::RemoveWhitespace, "se l\te\nc\rt\x0b\x0c"), "select");
    }

    #[test]
    fn compress_whitespace_folds_runs_to_one_space() {
        assert_eq!(t(T::CompressWhitespace, "a \t\n  b"), "a b");
        assert_eq!(t(T::CompressWhitespace, "union    select"), "union select");
        assert!(matches!(
            T::CompressWhitespace.apply(b"already single"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn cmd_line_normalises_shell_obfuscation() {
        // A space before `/` is deleted, so `cat /etc/passwd` and
        // `cat/etc/passwd` normalise to the same string. This is the documented
        // behaviour and the reason the transformation exists.
        assert_eq!(
            t(T::CmdLine, r#"/bin/cat /etc/passwd"#),
            "/bin/cat/etc/passwd"
        );
        // Quotes, carets and backslashes vanish.
        assert_eq!(t(T::CmdLine, r#"n"e"t"w"o"r"k"#), "network");
        assert_eq!(t(T::CmdLine, "c^m^d"), "cmd");
        assert_eq!(t(T::CmdLine, r"pin\g"), "ping");
        // Commas and semicolons become spaces.
        assert_eq!(t(T::CmdLine, "a,b;c"), "a b c");
        // A space before / or ( is deleted.
        assert_eq!(t(T::CmdLine, "cat /etc"), "cat/etc");
        assert_eq!(t(T::CmdLine, "nc ("), "nc(");
        // And everything lowercases.
        assert_eq!(t(T::CmdLine, "WGET"), "wget");
    }

    #[test]
    fn normalize_path_resolves_traversal() {
        assert_eq!(t(T::NormalizePath, "/a/b/../c"), "/a/c");
        assert_eq!(t(T::NormalizePath, "/a/./b"), "/a/b");
        assert_eq!(t(T::NormalizePath, "/a//b"), "/a/b");
        assert_eq!(t(T::NormalizePath, "a/b/../../c"), "c");
        // A traversal above the root is dropped, not preserved.
        assert_eq!(t(T::NormalizePath, "/../etc/passwd"), "/etc/passwd");
        // Above a relative root it is significant.
        assert_eq!(t(T::NormalizePath, "../etc/passwd"), "../etc/passwd");
        // Trailing slashes survive.
        assert_eq!(t(T::NormalizePath, "/a/b/"), "/a/b/");
    }

    #[test]
    fn normalize_path_win_folds_backslashes_first() {
        assert_eq!(t(T::NormalizePathWin, r"\a\b\..\c"), "/a/c");
        assert_eq!(
            t(T::NormalizePathWin, r"..\..\windows\system32"),
            "../../windows/system32"
        );
    }

    #[test]
    fn remove_comments_char_strips_delimiters_only() {
        assert_eq!(t(T::RemoveCommentsChar, "/*foo*/"), "foo");
        assert_eq!(t(T::RemoveCommentsChar, "a--b"), "ab");
        assert_eq!(t(T::RemoveCommentsChar, "a#b"), "ab");
        assert_eq!(t(T::RemoveCommentsChar, "<!--x-->"), "x");
    }

    #[test]
    fn replace_comments_collapses_inline_sql_comments() {
        // The classic inline-comment evasion.
        assert_eq!(t(T::ReplaceComments, "UN/*x*/ION"), "UN ION");
        assert_eq!(t(T::ReplaceComments, "a/**/b"), "a b");
        // An unterminated comment must not hide the tail from the operator by
        // being left intact.
        assert_eq!(t(T::ReplaceComments, "select/*rest"), "select ");
    }

    #[test]
    fn html_entity_decode_handles_named_decimal_and_hex() {
        assert_eq!(t(T::HtmlEntityDecode, "&lt;script&gt;"), "<script>");
        assert_eq!(t(T::HtmlEntityDecode, "&#60;&#62;"), "<>");
        assert_eq!(t(T::HtmlEntityDecode, "&#x3c;&#X3E;"), "<>");
        assert_eq!(t(T::HtmlEntityDecode, "&amp;&quot;"), "&\"");
        // The semicolon is optional, as browsers accept it missing.
        assert_eq!(t(T::HtmlEntityDecode, "&lt script"), "< script");
        // A bare ampersand stays put.
        assert_eq!(t(T::HtmlEntityDecode, "a & b"), "a & b");
        // An unknown entity is left alone rather than being eaten.
        assert_eq!(t(T::HtmlEntityDecode, "&unknown;"), "&unknown;");
    }

    #[test]
    fn url_decode_uni_decodes_percent_plus_and_iis_unicode() {
        assert_eq!(t(T::UrlDecodeUni, "%3Cscript%3E"), "<script>");
        assert_eq!(t(T::UrlDecodeUni, "a+b"), "a b");
        assert_eq!(t(T::UrlDecodeUni, "%u003c"), "<");
        // Full-width ASCII folds to its ASCII equivalent.
        assert_eq!(t(T::UrlDecodeUni, "%uff1cscript%uff1e"), "<script>");
        // Invalid or truncated escapes are preserved, never swallowed.
        assert_eq!(t(T::UrlDecodeUni, "%zz"), "%zz");
        assert_eq!(t(T::UrlDecodeUni, "%"), "%");
        assert_eq!(t(T::UrlDecodeUni, "%u12"), "%u12");
    }

    #[test]
    fn utf8_to_unicode_rewrites_non_ascii() {
        assert_eq!(t(T::Utf8ToUnicode, "a\u{20ac}b"), "a%u20acb");
        assert_eq!(t(T::Utf8ToUnicode, "\u{ff1c}"), "%uff1c");
    }

    #[test]
    fn utf8_to_unicode_passes_invalid_bytes_through() {
        // Not valid UTF-8. The transformation re-encodes what it understands
        // and leaves the rest, rather than dropping bytes.
        let out = T::Utf8ToUnicode.apply(&[b'a', 0xff, b'b']);
        assert_eq!(out.as_ref(), &[b'a', 0xff, b'b']);
    }

    #[test]
    fn js_decode_handles_every_escape_form() {
        assert_eq!(t(T::JsDecode, r"<script>"), "<script>");
        assert_eq!(t(T::JsDecode, r"\x3cscript\x3e"), "<script>");
        assert_eq!(t(T::JsDecode, r"\u{3c}"), "<");
        assert_eq!(t(T::JsDecode, r"\074"), "<");
        assert_eq!(t(T::JsDecode, r"\n\t"), "\n\t");
        // The full-width fold applies to the escape, not to a literal
        // full-width character, which jsDecode leaves alone.
        assert_eq!(t(T::JsDecode, r"\uff1c"), "<");
        assert_eq!(t(T::JsDecode, "＜"), "＜");
        // An escape of an ordinary character yields the character, which is
        // what collapses \S\E\L\E\C\T into SELECT.
        assert_eq!(t(T::JsDecode, r"\S\E\L\E\C\T"), "SELECT");
        // A leading-zero extended escape folds the same as the short form.
        assert_eq!(t(T::JsDecode, r"\u{0ff1c}"), "<");
    }

    #[test]
    fn escape_seq_decode_handles_c_escapes() {
        assert_eq!(t(T::EscapeSeqDecode, r"\x41\x42"), "AB");
        assert_eq!(t(T::EscapeSeqDecode, r"\101"), "A");
        assert_eq!(t(T::EscapeSeqDecode, r"\n"), "\n");
        assert_eq!(t(T::EscapeSeqDecode, r"\?"), "?");
    }

    #[test]
    fn css_decode_handles_hex_escapes_and_terminators() {
        assert_eq!(t(T::CssDecode, r"\3c script\3e"), "<script>");
        assert_eq!(t(T::CssDecode, r"\00003c"), "<");
        // The classic CSS expression evasion.
        assert_eq!(t(T::CssDecode, r"\65 xpression"), "expression");
        // A backslash before a non-hex character yields that character. Note
        // `\e` is a *hex* escape (U+000E), not the letter e.
        assert_eq!(t(T::CssDecode, r"\s\z\p"), "szp");
        assert_eq!(T::CssDecode.apply(br"\e").as_ref(), &[0x0e]);
    }

    #[test]
    fn base64_decode_stops_at_the_first_invalid_byte() {
        assert_eq!(t(T::Base64Decode, "PHNjcmlwdD4="), "<script>");
        // CR and LF are ignored, so a wrapped payload decodes in full.
        assert_eq!(t(T::Base64Decode, "PHNj\r\ncmlwdD4="), "<script>");
        // Any other byte outside the alphabet ends the decode, and what was
        // decoded up to that point is returned.
        assert_eq!(t(T::Base64Decode, "PHNjcmlw dD4="), "<scrip");
        assert_eq!(t(T::Base64Decode, "PHNj\0cmlw"), "<sc");
        // A truncated final group still decodes as far as it can.
        assert_eq!(t(T::Base64Decode, "PHNjcmlwdD"), "<script");
        assert_eq!(t(T::Base64Decode, ""), "");
    }

    #[test]
    fn css_decode_resolves_code_points_not_low_bytes() {
        // A three-digit escape whose value exceeds one byte must not be
        // truncated: U+0101, encoded as UTF-8.
        assert_eq!(T::CssDecode.apply(br"\101").as_ref(), "\u{101}".as_bytes());
        // A zero code point is invalid and resolves to U+FFFD.
        assert_eq!(
            T::CssDecode.apply(br"\0").as_ref(),
            char::REPLACEMENT_CHARACTER.to_string().as_bytes()
        );
        // A trailing backslash with nothing after it is dropped.
        assert_eq!(T::CssDecode.apply(br"a\").as_ref(), b"a");
    }

    #[test]
    fn transformations_compose_the_way_crs_stacks_them() {
        // t:urlDecodeUni,t:htmlEntityDecode is the most common CRS pair.
        let stacked = [T::UrlDecodeUni, T::HtmlEntityDecode, T::Lowercase];
        let mut value: Vec<u8> = b"%26lt%3BSCRIPT%26gt%3B".to_vec();
        for step in stacked {
            value = step.apply(&value).into_owned();
        }
        assert_eq!(String::from_utf8_lossy(&value), "<script>");
    }

    #[test]
    fn every_transformation_handles_empty_input() {
        for kind in [
            T::None,
            T::Base64Decode,
            T::CmdLine,
            T::CompressWhitespace,
            T::CssDecode,
            T::EscapeSeqDecode,
            T::HexEncode,
            T::HtmlEntityDecode,
            T::JsDecode,
            T::Length,
            T::Lowercase,
            T::NormalizePath,
            T::NormalizePathWin,
            T::RemoveCommentsChar,
            T::RemoveNulls,
            T::RemoveWhitespace,
            T::ReplaceComments,
            T::Sha1,
            T::UrlDecodeUni,
            T::Utf8ToUnicode,
        ] {
            let _ = kind.apply(b"");
        }
    }

    #[test]
    fn no_transformation_panics_on_arbitrary_bytes() {
        // Decoders run on attacker-controlled bytes, so index arithmetic near
        // a truncated escape must not panic.
        let nasty: Vec<Vec<u8>> = vec![
            b"%".to_vec(),
            b"%u".to_vec(),
            b"%uff".to_vec(),
            b"\\".to_vec(),
            b"\\u".to_vec(),
            b"\\u{".to_vec(),
            b"\\u{fffff".to_vec(),
            b"\\x".to_vec(),
            b"&".to_vec(),
            b"&#".to_vec(),
            b"&#x".to_vec(),
            b"/*".to_vec(),
            b"<!--".to_vec(),
            b"--".to_vec(),
            vec![0xff, 0xfe, 0x00],
            vec![0x80],
            vec![b'\\', 0xff],
        ];
        for kind in [
            T::Base64Decode,
            T::CmdLine,
            T::CompressWhitespace,
            T::CssDecode,
            T::EscapeSeqDecode,
            T::HtmlEntityDecode,
            T::JsDecode,
            T::NormalizePath,
            T::NormalizePathWin,
            T::RemoveCommentsChar,
            T::ReplaceComments,
            T::UrlDecodeUni,
            T::Utf8ToUnicode,
        ] {
            for input in &nasty {
                let _ = kind.apply(input);
            }
        }
    }
    #[test]
    fn decoder_edge_branches() {
        // urlDecodeUni leaves a malformed escape verbatim.
        assert_eq!(t(T::UrlDecodeUni, "%uZZZZ"), "%uZZZZ");
        assert_eq!(t(T::UrlDecodeUni, "%u"), "%u");
        assert_eq!(t(T::UrlDecodeUni, "%GG"), "%GG");
        assert_eq!(t(T::UrlDecodeUni, "%"), "%");
        // The single-character C escapes.
        assert_eq!(
            T::EscapeSeqDecode.apply(br"\a\b\f\v").into_owned(),
            vec![0x07, 0x08, 0x0c, 0x0b]
        );
        // A CSS backslash-newline is a line continuation and vanishes.
        assert_eq!(
            t(
                T::CssDecode,
                "a\\
b"
            ),
            "ab"
        );
        // A zero code point resolves to the replacement character.
        assert_eq!(t(T::CssDecode, "\\0"), "\u{FFFD}");
        // Base64 with a 2- and 3-char remainder still decodes the partial bytes.
        assert_eq!(t(T::Base64Decode, "TWE"), "Ma");
        assert_eq!(t(T::Base64Decode, "TQ"), "M");
    }
}
