# Parapet

[![CI](https://github.com/barbacane-dev/parapet/actions/workflows/ci.yml/badge.svg)](https://github.com/barbacane-dev/parapet/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![CRS @rx coverage](https://img.shields.io/badge/CRS%20v4.9.0%20%40rx-273%2F273-brightgreen)](crates/parapet-conformance)

A SecLang rule engine in pure Rust, compatible with the OWASP Core Rule Set.

No C, no C++, no cgo, no FFI, no garbage collector. One dependency-light crate
you can embed in a proxy, a server, or a build step.

```rust
use parapet::regex_compat;

// Compile a SecLang @rx operand, with the CRS corpus as the compatibility bar.
let compiled = regex_compat::compile(r"(?i)\bunion\b.{1,100}?\bselect\b")?;
assert!(compiled.regex.is_match("1 UNION SELECT password FROM users"));
```

> **Status: early.** The regex compatibility layer is implemented and verified
> against CRS v4.9.0. The parser, operators, transformations and phase engine
> are in progress. The scope table below is the roadmap. Do not deploy this.

## Why

Every Rust proxy that offers a WAF today either binds to libmodsecurity over
C++ FFI, links the Go Coraza engine through cgo, or ships a bespoke rule format
that cannot consume the Core Rule Set. There is no pure-Rust SecLang engine.

That matters because SecLang plus the Core Rule Set is the only rule supply
chain that exists: a shared corpus, a shared test suite (`go-ftw`), and rules
maintained by people who do that full time. A WAF with its own rule format
starts from zero and stays there.

## Design commitments

**Compilation is separate from evaluation.** A rule set is parsed and compiled
once, producing a program that owns its compiled regexes and multi-pattern
automata. Evaluation borrows it. Embedders that compile ahead of time, in a
build step or into a sealed artifact, pay no rule-compilation cost per request.
For scale: compiling the full CRS `@rx` corpus takes about 155 ms, which is
nothing as a build step and ruinous per request.

**An unrecognised construct is an error, never a skip.** A directive, operator,
transformation or action that Parapet does not implement fails compilation. An
engine that ignores what it cannot parse silently converts a rule into a
bypass. Partial understanding is not an acceptable outcome for a security
control, so Parapet refuses instead.

**Conformance is measured.** "CRS-compatible" means passing the Core Rule Set's
own regression corpus under `go-ftw`, not a list of features in a README. See
[`crates/parapet-conformance`](crates/parapet-conformance).

## Verified so far

Regex compatibility, measured against CRS v4.9.0 (`rules/*.conf`, 660 `SecRule`
plus 7 `SecAction`, 299 `@rx` operands, 273 unique):

| Result | Count |
|---|---|
| Compile unmodified with the `regex` crate | 268 / 273 |
| Compile after a lexical repair pass | 273 / 273 |
| Requiring PCRE-only features (lookaround, backreferences) | 0 |
| Accepted by Go/RE2, for cross-reference | 273 / 273 |

The 5 patterns needing repair use a literal `{`/`}` outside a counted
repetition, or a redundant escape inside a character class. PCRE and RE2 accept
both; `regex-syntax` does not. Repairs run only after a direct compile fails,
so an accepted pattern is never rewritten, and the 5 repairs were
differential-tested against Go/RE2 verdicts for the originals over 297,129
inputs with **0 disagreements**.

Consequence: CRS needs no PCRE, and the `regex` crate's linear-time guarantee
means no ReDoS surface from operator-supplied rules.

## Scope

SecLang defines far more than the Core Rule Set uses. Parapet targets what CRS
actually needs, measured from v4.9.0:

| Surface | Distinct | Status |
|---|---|---|
| `@rx` compatibility layer | 273 patterns | done |
| Operators | 18 | todo |
| Transformations | 20 (plus `none`) | todo |
| Variables / collections | 32 | todo |
| `ctl:` actions | 6 | todo |
| Phases | 5 | todo |
| Directives (in `rules/`) | 4 | todo |

Eighteen operators, not the 35+ SecLang defines: `@rx`, `@lt`, `@eq`, `@ge`,
`@pmFromFile`, `@gt`, `@pm`, `@within`, `@endsWith`, `@validateByteRange`,
`@streq`, `@contains`, `@validateUrlEncoding`, `@ipMatch`, `@detectXSS`,
`@detectSQLi`, `@unconditionalMatch`, `@validateUtf8Encoding`.

Known hard parts, called out rather than discovered later: multipart parsing
edge cases, `XML` selection (175 target references in CRS), persistent
collections, and `MATCHED_VARS` semantics.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Contributions are accepted under the same terms, under a DCO
sign-off. See [CONTRIBUTING.md](CONTRIBUTING.md).

Permissive on purpose: an engine is only worth extracting if anyone can embed
it, including proxies that compete with each other.

## Not affiliated

Parapet implements the SecLang language. It contains no ModSecurity or Coraza
source code and is not affiliated with, endorsed by, or derived from
ModSecurity, Coraza, or OWASP. "ModSecurity" and "OWASP" are trademarks of
their respective owners.

[Barbacane](https://github.com/barbacane-dev/barbacane) is Parapet's first
consumer, and Parapet is deliberately independent of it: nothing in this crate
knows what a Barbacane is.
