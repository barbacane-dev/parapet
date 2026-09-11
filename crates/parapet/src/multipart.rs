//! Parsing `multipart/form-data` bodies.
//!
//! Multipart is where WAF bypasses live, because servers disagree about
//! malformed input: a filename with an embedded quote, a header the parser
//! skips, a boundary that does not quite match. CRS dedicates a whole rule
//! file to it (`REQUEST-922-MULTIPART-ATTACK`) and 920120 exists specifically
//! to catch filenames crafted to slip past a lenient parser.
//!
//! This parser is therefore deliberately literal: it reports what is actually
//! in the bytes, including the raw header lines, rather than normalising them
//! away. Rules cannot flag what the parser has already tidied up.

/// One part of a multipart body.
#[derive(Debug, Clone, Default)]
pub struct Part {
    /// The `name` parameter of `Content-Disposition`, if present.
    pub name: Option<String>,
    /// The `filename` parameter, present on file uploads.
    pub filename: Option<String>,
    /// The part's headers as raw `name: value` lines, in order.
    pub header_lines: Vec<(String, Vec<u8>)>,
    /// The part's body.
    pub content: Vec<u8>,
}

/// Everything a multipart body yields.
#[derive(Debug, Default)]
pub struct Multipart {
    /// The parts, in order.
    pub parts: Vec<Part>,
}

/// Pull the boundary out of a `Content-Type` header value.
pub fn boundary_of(content_type: &str) -> Option<String> {
    for param in content_type.split(';').skip(1) {
        let param = param.trim();
        let (key, value) = param.split_once('=')?;
        if key.trim().eq_ignore_ascii_case("boundary") {
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value);
            if value.is_empty() {
                return None;
            }
            return Some(value.to_string());
        }
    }
    None
}

/// Parse a multipart body.
///
/// Returns an error when the body has no usable structure, which the caller
/// surfaces as `REQBODY_ERROR`. A body that cannot be split into parts must
/// not be reported as clean.
pub fn parse(body: &[u8], boundary: &str) -> Result<Multipart, String> {
    let delimiter = format!("--{boundary}");
    let positions = find_all(body, delimiter.as_bytes());
    if positions.is_empty() {
        return Err("no boundary found in multipart body".to_string());
    }

    let mut out = Multipart::default();
    for (i, start) in positions.iter().enumerate() {
        let after = start + delimiter.len();
        // `--boundary--` closes the body; anything after it is an epilogue.
        if body[after..].starts_with(b"--") {
            break;
        }
        let content_start = match skip_line_break(body, after) {
            Some(pos) => pos,
            // A delimiter not followed by a line break is not a real one.
            None => continue,
        };
        let content_end = positions
            .get(i + 1)
            .map(|next| trim_trailing_break(body, *next))
            .unwrap_or(body.len());
        if content_end < content_start {
            continue;
        }
        out.parts
            .push(parse_part(&body[content_start..content_end]));
    }

    if out.parts.is_empty() {
        return Err("multipart body contains no parts".to_string());
    }
    Ok(out)
}

fn parse_part(raw: &[u8]) -> Part {
    let mut part = Part::default();

    // Headers end at the first blank line. A part with no blank line has no
    // body, which is malformed but still worth reporting.
    let split = find(raw, b"\r\n\r\n")
        .map(|i| (i, i + 4))
        .or_else(|| find(raw, b"\n\n").map(|i| (i, i + 2)));
    let (header_end, body_start) = match split {
        Some(pair) => pair,
        None => (raw.len(), raw.len()),
    };

    for line in split_lines(&raw[..header_end]) {
        if line.is_empty() {
            continue;
        }
        let name = match find(line, b":") {
            Some(i) => String::from_utf8_lossy(&line[..i]).trim().to_string(),
            // A header line with no colon is malformed. It is kept under an
            // empty name so rule 922130, which looks for exactly that shape,
            // can still see it.
            None => String::new(),
        };
        // The value is the whole line: CRS rules match against
        // `^content-type\s*:\s*(.*)$`, so the name must stay in the value.
        part.header_lines.push((name.clone(), line.to_vec()));

        if name.eq_ignore_ascii_case("content-disposition") {
            let value = String::from_utf8_lossy(line);
            part.name = parameter_of(&value, "name");
            part.filename = parameter_of(&value, "filename");
        }
    }

    part.content = raw[body_start..].to_vec();
    part
}

/// Extract a `key="value"` parameter from a header line.
///
/// Deliberately literal about quoting: the value is taken up to the closing
/// quote with no unescaping, because a filename containing a quote or a
/// backslash is precisely what rule 920120 is looking for, and normalising it
/// here would hide it.
fn parameter_of(header: &str, key: &str) -> Option<String> {
    let bytes = header.as_bytes();
    let needle = format!("{key}=");
    let mut search = 0;
    while let Some(offset) = find(&bytes[search..], needle.as_bytes()) {
        let at = search + offset;
        // Must be preceded by a separator, so `filename` does not match
        // inside `xfilename`.
        let preceded_ok =
            at == 0 || matches!(bytes[at - 1], b';' | b' ' | b'\t' | b'*') || bytes[at - 1] == b'"';
        if !preceded_ok {
            search = at + needle.len();
            continue;
        }
        let rest = &header[at + needle.len()..];
        return Some(match rest.strip_prefix('"') {
            Some(quoted) => match quoted.find('"') {
                Some(end) => quoted[..end].to_string(),
                // An unterminated quote is malformed; take what is there.
                None => quoted.to_string(),
            },
            None => rest
                .split([';', '\r', '\n'])
                .next()
                .unwrap_or("")
                .trim()
                .to_string(),
        });
    }
    None
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < haystack.len() {
        match find(&haystack[at..], needle) {
            Some(offset) => {
                out.push(at + offset);
                at += offset + needle.len();
            }
            None => break,
        }
    }
    out
}

/// Skip the CRLF or LF that must follow a boundary delimiter.
fn skip_line_break(body: &[u8], at: usize) -> Option<usize> {
    if body[at..].starts_with(b"\r\n") {
        Some(at + 2)
    } else if body[at..].starts_with(b"\n") {
        Some(at + 1)
    } else {
        None
    }
}

/// A part's content excludes the line break that precedes the next boundary.
fn trim_trailing_break(body: &[u8], next_boundary: usize) -> usize {
    if next_boundary >= 2 && &body[next_boundary - 2..next_boundary] == b"\r\n" {
        next_boundary - 2
    } else if next_boundary >= 1 && body[next_boundary - 1] == b'\n' {
        next_boundary - 1
    } else {
        next_boundary
    }
}

fn split_lines(raw: &[u8]) -> Vec<&[u8]> {
    raw.split(|b| *b == b'\n')
        .map(|line| match line.last() {
            Some(b'\r') => &line[..line.len() - 1],
            _ => line,
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const B: &str = "----WebKitFormBoundaryABC";

    fn body(parts: &str) -> Vec<u8> {
        parts.replace('\n', "\r\n").into_bytes()
    }

    #[test]
    fn reads_the_boundary_from_a_content_type() {
        assert_eq!(
            boundary_of("multipart/form-data; boundary=abc123").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            boundary_of(r#"multipart/form-data; boundary="quoted""#).as_deref(),
            Some("quoted")
        );
        assert_eq!(boundary_of("multipart/form-data"), None);
        assert_eq!(boundary_of("multipart/form-data; boundary="), None);
    }

    #[test]
    fn parses_a_simple_field() {
        let raw = body(&format!(
            "--{B}\nContent-Disposition: form-data; name=\"field\"\n\nvalue\n--{B}--\n"
        ));
        let m = parse(&raw, B).unwrap();
        assert_eq!(m.parts.len(), 1);
        assert_eq!(m.parts[0].name.as_deref(), Some("field"));
        assert_eq!(m.parts[0].content, b"value");
        assert!(m.parts[0].filename.is_none());
    }

    #[test]
    fn parses_a_file_upload() {
        let raw = body(&format!(
            "--{B}\nContent-Disposition: form-data; name=\"upload\"; filename=\"evil.php\"\nContent-Type: application/x-php\n\n<?php ?>\n--{B}--\n"
        ));
        let m = parse(&raw, B).unwrap();
        assert_eq!(m.parts[0].name.as_deref(), Some("upload"));
        assert_eq!(m.parts[0].filename.as_deref(), Some("evil.php"));
        assert_eq!(m.parts[0].content, b"<?php ?>");
        assert_eq!(m.parts[0].header_lines.len(), 2);
    }

    #[test]
    fn parses_several_parts() {
        let raw = body(&format!(
            "--{B}\nContent-Disposition: form-data; name=\"a\"\n\n1\n--{B}\nContent-Disposition: form-data; name=\"b\"\n\n2\n--{B}--\n"
        ));
        let m = parse(&raw, B).unwrap();
        assert_eq!(m.parts.len(), 2);
        assert_eq!(m.parts[1].name.as_deref(), Some("b"));
        assert_eq!(m.parts[1].content, b"2");
    }

    #[test]
    fn a_filename_containing_a_quote_survives_intact() {
        // This is the bypass rule 920120 looks for. Normalising the filename
        // here would hide it from the rule.
        let raw = body(&format!(
            "--{B}\nContent-Disposition: form-data; name=\"f\"; filename=\"a\"b.php\"\n\nx\n--{B}--\n"
        ));
        let m = parse(&raw, B).unwrap();
        assert_eq!(m.parts[0].filename.as_deref(), Some("a"));
        // The raw header line still carries the whole thing for rules that
        // inspect MULTIPART_PART_HEADERS.
        let line = String::from_utf8_lossy(&m.parts[0].header_lines[0].1).into_owned();
        assert!(line.contains(r#"filename="a"b.php""#));
    }

    #[test]
    fn header_lines_keep_their_name_in_the_value() {
        // CRS matches `^content-type\s*:\s*(.*)$` against the value.
        let raw = body(&format!(
            "--{B}\nContent-Disposition: form-data; name=\"f\"\nContent-Type: text/plain\n\nx\n--{B}--\n"
        ));
        let m = parse(&raw, B).unwrap();
        let (name, value) = &m.parts[0].header_lines[1];
        assert_eq!(name, "Content-Type");
        assert_eq!(value, b"Content-Type: text/plain");
    }

    #[test]
    fn a_header_line_with_no_colon_is_kept() {
        // Rule 922130 looks for exactly this malformation.
        let raw = body(&format!(
            "--{B}\nContent-Disposition: form-data; name=\"f\"\nnot a header\n\nx\n--{B}--\n"
        ));
        let m = parse(&raw, B).unwrap();
        assert!(m.parts[0]
            .header_lines
            .iter()
            .any(|(name, value)| name.is_empty() && value == b"not a header"));
    }

    #[test]
    fn tolerates_bare_line_feeds() {
        let raw = format!("--{B}\nContent-Disposition: form-data; name=\"f\"\n\nvalue\n--{B}--\n")
            .into_bytes();
        let m = parse(&raw, B).unwrap();
        assert_eq!(m.parts[0].content, b"value");
    }

    #[test]
    fn a_body_with_no_boundary_is_an_error() {
        assert!(parse(b"just some bytes", B).is_err());
    }

    #[test]
    fn a_body_with_no_parts_is_an_error() {
        let raw = body(&format!("--{B}--\n"));
        assert!(parse(&raw, B).is_err());
    }

    #[test]
    fn an_unterminated_body_still_yields_its_parts() {
        // The closing delimiter is missing; the payload is still there.
        let raw = body(&format!(
            "--{B}\nContent-Disposition: form-data; name=\"f\"\n\npayload\n"
        ));
        let m = parse(&raw, B).unwrap();
        assert_eq!(m.parts.len(), 1);
        assert!(String::from_utf8_lossy(&m.parts[0].content).contains("payload"));
    }

    #[test]
    fn an_unquoted_filename_parameter_is_read_to_the_next_separator() {
        let raw = body(&format!(
            "--{B}\nContent-Disposition: form-data; name=f; filename=bare.txt\n\nx\n--{B}--\n"
        ));
        let m = parse(&raw, B).unwrap();
        assert_eq!(m.parts[0].name.as_deref(), Some("f"));
        assert_eq!(m.parts[0].filename.as_deref(), Some("bare.txt"));
    }

    #[test]
    fn a_parameter_name_inside_a_longer_word_is_not_matched() {
        // `xfilename=` must not be read as `filename=`.
        let raw = body(&format!(
            "--{B}\nContent-Disposition: form-data; xfilename=\"trick\"; name=\"real\"\n\nx\n--{B}--\n"
        ));
        let m = parse(&raw, B).unwrap();
        assert_eq!(m.parts[0].name.as_deref(), Some("real"));
        assert!(m.parts[0].filename.is_none());
    }

    #[test]
    fn an_unterminated_quoted_filename_takes_what_is_there() {
        let raw = body(&format!(
            "--{B}\nContent-Disposition: form-data; name=\"f\"; filename=\"open\n\nx\n--{B}--\n"
        ));
        let m = parse(&raw, B).unwrap();
        assert_eq!(m.parts[0].filename.as_deref(), Some("open"));
    }

    #[test]
    fn a_part_with_no_header_separator_has_no_body() {
        let raw = body(&format!("--{B}\nleftover-no-blank-line\n--{B}--\n"));
        let m = parse(&raw, B).unwrap();
        assert_eq!(m.parts.len(), 1);
        assert!(m.parts[0].content.is_empty());
    }

    #[test]
    fn a_boundary_with_no_following_line_break_is_not_a_part() {
        // `--BOUND` immediately followed by more text (no CRLF) is not a real
        // delimiter, so no part opens there.
        let raw = format!("--{B}xtra\r\n--{B}--\r\n").into_bytes();
        assert!(parse(&raw, B).is_err());
    }

    #[test]
    fn does_not_panic_on_arbitrary_bytes() {
        for input in [
            &b"--"[..],
            b"----WebKitFormBoundaryABC",
            b"----WebKitFormBoundaryABC\r\n",
            b"----WebKitFormBoundaryABC--",
            &[0xff, 0xfe, 0x00],
        ] {
            let _ = parse(input, B);
        }
    }
}
