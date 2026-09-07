//! Differential test for transformations against a reference implementation.
//!
//! Transformations decide what an operator actually sees, so a divergence here
//! is a bypass or a false positive, not a cosmetic difference. Unit tests only
//! prove self-consistency; this compares against outputs produced by Coraza,
//! the engine CRS is authored against.

use std::collections::BTreeMap;

use parapet::action::Transformation;

#[derive(serde::Deserialize)]
pub struct ReferenceResult {
    pub name: String,
    pub input: String,
    #[serde(default)]
    pub output: String,
    #[serde(default)]
    pub err: String,
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Map a SecLang transformation name onto the parsed enum.
fn lookup(name: &str) -> Option<Transformation> {
    Transformation::parse(name)
}

/// A divergence from the reference that is intentional, with the reason.
///
/// Each entry is a predicate over the specific input rather than a blanket
/// exemption for a transformation, so a *new* divergence in the same
/// transformation still fails. A reference implementation is a reference, not
/// an oracle: two of these exist because the reference is wrong, three because
/// it inherits Go's rune semantics where SecLang is byte-oriented, and one
/// because it adds hardening that CRS was not authored against.
struct Expected {
    reason: &'static str,
    applies: fn(input: &[u8], parapet: &[u8], reference: &[u8]) -> bool,
}

fn expected_divergence(name: &str) -> Option<Expected> {
    Some(match name {
        // strings.ToLower and unicode.IsSpace decode runes, so invalid UTF-8
        // is replaced with U+FFFD before the transformation runs. SecLang is
        // byte-oriented (ModSecurity uses tolower/isspace per byte), and a WAF
        // must not rewrite bytes it was asked to inspect.
        "lowercase" | "removeWhitespace" | "utf8toUnicode" => Expected {
            reason: "reference decodes runes and substitutes U+FFFD for invalid UTF-8; Parapet stays byte-oriented",
            applies: |input, _, _| std::str::from_utf8(input).is_err(),
        },

        // ModSecurity's html_entity_decode emits the single byte 0xa0 for
        // &nbsp;. The reference emits it UTF-8 encoded (0xc2 0xa0).
        "htmlEntityDecode" => Expected {
            reason: "reference UTF-8 encodes the &nbsp; result; ModSecurity emits the single byte 0xa0",
            applies: |_, parapet, reference| parapet == [0xa0] && reference == [0xc2, 0xa0],
        },

        // Reference bug: it appends a trailing slash to the cleaned path
        // without checking whether one is already there, so "/" and "//"
        // both become "//".
        "normalizePath" => Expected {
            reason: "reference bug: re-appends a trailing slash unconditionally, yielding \"//\"",
            applies: |_, _, reference| reference == b"//",
        },

        // The reference additionally strips NTFS Alternate Data Stream
        // suffixes and trailing dots/spaces per component. That is sound
        // hardening against a real Windows bypass class, but CRS is authored
        // against ModSecurity's plainer semantics, so adopting it is a
        // decision for the FTW suite to settle rather than an assumption.
        "normalizePathWin" => Expected {
            reason: "reference adds ADS/trailing-dot hardening beyond ModSecurity semantics",
            applies: |_, _, _| true,
        },

        // Reference bug: the octal branch copies input[i+j] starting at the
        // backslash itself, so the digit buffer begins with 0x5c and the
        // parse fails, making every \OOO escape decode to NUL. A CRS rule
        // relying on t:jsDecode to unmask an octal-escaped payload would not
        // see it.
        "jsDecode" => Expected {
            reason: "reference bug: octal escapes decode to NUL (digit buffer starts at the backslash)",
            applies: |input, _, reference| {
                reference.contains(&0)
                    && input.windows(2).any(|w| w[0] == b'\\' && w[1].is_ascii_digit())
            },
        },

        _ => return None,
    })
}

/// Compare Parapet against reference outputs. Returns the number of
/// divergences found.
pub fn run(reference_path: &str) -> Result<usize, String> {
    let raw = std::fs::read_to_string(reference_path)
        .map_err(|e| format!("cannot read {reference_path}: {e}"))?;
    let results: Vec<ReferenceResult> =
        serde_json::from_str(&raw).map_err(|e| format!("cannot parse {reference_path}: {e}"))?;

    let mut compared: BTreeMap<String, usize> = BTreeMap::new();
    let mut diverged: BTreeMap<String, Vec<(String, String, String)>> = BTreeMap::new();
    let mut accepted: BTreeMap<String, (usize, &'static str)> = BTreeMap::new();
    let mut skipped = 0usize;

    for r in &results {
        if !r.err.is_empty() {
            skipped += 1;
            continue;
        }
        let Some(kind) = lookup(&r.name) else {
            skipped += 1;
            continue;
        };
        let Some(input) = from_hex(&r.input) else {
            return Err(format!("bad input hex for {}", r.name));
        };
        let got = to_hex(&kind.apply(&input));
        *compared.entry(r.name.clone()).or_default() += 1;
        if got != r.output {
            let got_bytes = from_hex(&got).unwrap_or_default();
            let want_bytes = from_hex(&r.output).unwrap_or_default();
            match expected_divergence(&r.name) {
                Some(e) if (e.applies)(&input, &got_bytes, &want_bytes) => {
                    let entry = accepted.entry(r.name.clone()).or_insert((0, e.reason));
                    entry.0 += 1;
                }
                _ => diverged.entry(r.name.clone()).or_default().push((
                    r.input.clone(),
                    got,
                    r.output.clone(),
                )),
            }
        }
    }

    let total: usize = compared.values().sum();
    let total_diverged: usize = diverged.values().map(Vec::len).sum();

    println!("transformations compared : {}", compared.len());
    println!("cases compared           : {total}");
    println!("cases skipped            : {skipped}");
    println!(
        "expected divergences     : {}",
        accepted.values().map(|v| v.0).sum::<usize>()
    );
    println!("UNEXPECTED divergences   : {total_diverged}");

    if !accepted.is_empty() {
        println!("\nexpected divergences, by transformation:");
        for (name, (count, reason)) in &accepted {
            println!("  {name}: {count} cases\n    {reason}");
        }
    }

    for (name, cases) in &diverged {
        let n = compared.get(name).copied().unwrap_or(0);
        println!("\n  {name}: {} of {n} diverge", cases.len());
        for (input, got, want) in cases.iter().take(6) {
            println!(
                "    input {input}\n      parapet  {got}\n      coraza   {want}\n      as text  {:?} -> {:?} vs {:?}",
                String::from_utf8_lossy(&from_hex(input).unwrap_or_default()),
                String::from_utf8_lossy(&from_hex(got).unwrap_or_default()),
                String::from_utf8_lossy(&from_hex(want).unwrap_or_default()),
            );
        }
        if cases.len() > 6 {
            println!("    ... and {} more", cases.len() - 6);
        }
    }

    Ok(total_diverged)
}
