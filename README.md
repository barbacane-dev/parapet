# Parapet

[![CI](https://github.com/barbacane-dev/parapet/actions/workflows/ci.yml/badge.svg)](https://github.com/barbacane-dev/parapet/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![CRS @rx coverage](https://img.shields.io/badge/CRS%20v4.9.0%20%40rx-273%2F273-brightgreen)](crates/parapet-conformance)
[![CRS parse coverage](https://img.shields.io/badge/CRS%20v4.9.0%20directives-697%2F697-brightgreen)](crates/parapet-conformance)
[![CRS regression suite](https://img.shields.io/badge/CRS%20regression%20suite-94.3%25-yellowgreen)](crates/parapet-conformance)

A SecLang rule engine in pure Rust, compatible with the OWASP Core Rule Set.

No C, no C++, no cgo, no FFI, no garbage collector. One dependency-light crate
you can embed in a proxy, a server, or a build step.

```rust
use parapet::regex_compat;

// Compile a SecLang @rx operand, with the CRS corpus as the compatibility bar.
let compiled = regex_compat::compile(r"(?i)\bunion\b.{1,100}?\bselect\b")?;
assert!(compiled.regex.is_match("1 UNION SELECT password FROM users"));
```

> **Status: early, but measured.** Parapet loads the full OWASP Core Rule Set
> and passes **94.3% of the CRS regression suite** (3,635 of 3,853 stages) with
> the configuration CRS documents for its own tests. Urlencoded, multipart, XML
> and JSON bodies are all parsed. Two operators (`@detectSQLi`, `@detectXSS`)
> still refuse to compile. Do not deploy this: the remaining 5.7% is where the
> bypasses live, and a WAF is only as good as its worst gap.

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

## Cost per request

Measured with the full Core Rule Set at paranoia level 1, 591 rules, on an
M-series laptop (`crates/parapet-conformance/tools/bench_inspect.rs`):

| Request | p50 | p99 |
|---|---|---|
| GET, no query string | 311 µs | 341 µs |
| GET, one short parameter | 344 µs | 381 µs |
| GET, ten parameters | 591 µs | 631 µs |
| POST, small form body | 382 µs | 416 µs |
| POST, 4 KB JSON body | 734 µs | 785 µs |
| GET, SQLi (blocks) | 346 µs | 384 µs |

This is what running a full rule set costs, not overhead that can be tuned
away: it is 591 rules, each applying its transformations and evaluating its
operator against every target the rule names. Cost scales with the number of
inspected values, which is why ten parameters costs roughly twice what one
does.

Two things follow. Inspection dominates any per-request budget it shares, so
it belongs behind a decision about which routes need it rather than switched on
globally by reflex. And the effective lever is the size of the rule set: a
lower paranoia level, or scoping rules to the operations that can actually be
attacked in that way, changes this number far more than micro-optimisation
does. An earlier attempt to remove the per-rule value copies bought 7%.

## Sealing a rule set into a host artifact

The `serde` feature serialises a parsed rule set, so a host can validate it at
build time, store the result, and rebuild the automata once at startup rather
than re-parsing on every boot. This is what makes an unknown directive a build
failure rather than a runtime surprise.

```toml
parapet = { version = "0.0", features = ["serde"] }
```

Measured on CRS v4.9.0 (`cargo run -p parapet-conformance -- seal <rules>`):

| | |
|---|---|
| Source `.conf` | 599 KiB |
| Serialised rule set | 600 KiB (1.03x source) |
| Rebuild from sealed form | 316 ms, once per process |

The rebuild cost is regex programs plus the Aho-Corasick automata for the 23
`@pmFromFile` operators. It is paid per process, not per request, but it is not
free: a host that hot-reloads rule sets pays it on every reload.

## Scope

SecLang defines far more than the Core Rule Set uses. Parapet targets what CRS
actually needs, measured from v4.9.0:

| Surface | Distinct | Parsed | Evaluated |
|---|---|---|---|
| `@rx` compatibility layer | 273 patterns | yes | n/a |
| Directives (in `rules/`) | 4 | yes | no |
| Operators | 18 | yes | **16 of 18** |
| Rule chaining, `skipAfter`, `setvar`, anomaly scoring | | yes | **yes** |
| Transformations | 20 (plus `none`) | yes | **yes** |
| Variables / collections | 32 | yes | **32 of 32** |
| Actions | 23 | yes | most |
| Body formats | 4 | n/a | **urlencoded, multipart, XML, JSON** |
| `ctl:` actions | 7 | yes | **yes** |
| Phases | 5 | yes | **yes** |

Parsing CRS v4.9.0 yields 660 `SecRule`, 7 `SecAction`, 29 `SecMarker` and 1
`SecComponentSignature` with zero errors, and CI asserts those counts so a
parser that quietly stops recognising a construct fails the build rather than
returning fewer rules.

**CRS regression suite: 3,635 of 3,853 stages pass (94.3%).** The corpus is
CRS's own, run in process with the configuration `tests/regression/README.md`
documents. CI gates on a ratcheting baseline, so the number can only go up.

Where the remaining 218 failures are, in order:

| Cause | Stages | Note |
|---|---|---|
| Individual rule gaps | ~180 | a genuine long tail, nothing above 24 stages |
| `@detectSQLi` / `@detectXSS` missing | 30 | rules 941100/941101/942100/942101 |
| Over-matching | 6 | `942440` leads, 3 stages |

The body-format gaps are closed. What remains is per-rule semantics, which is
slower per point than the structural work was.

Libinjection is not the dominant gap. That was worth measuring rather than
assuming: it is under 10% of what is left, and the earlier plan had it as the
obvious next task.

End to end against CRS v4.9.0 at the default paranoia level: 12 attack
requests, 6 benign, 0 wrong verdicts, 1 known gap (the libinjection SQLi rule).
Blocking comes from CRS rule 949110 on accumulated anomaly score, exactly as a
real deployment would.

All 20 transformations are compared against a reference implementation over
14,480 cases with zero unexpected divergences. Every accepted divergence is a
predicate over specific inputs with a written reason, not a blanket exemption,
so a new one still fails the build. Two of them exist because the reference is
wrong; that harness found both.

Eighteen operators, not the 35+ SecLang defines: `@rx`, `@lt`, `@eq`, `@ge`,
`@pmFromFile`, `@gt`, `@pm`, `@within`, `@endsWith`, `@validateByteRange`,
`@streq`, `@contains`, `@validateUrlEncoding`, `@ipMatch`, `@detectXSS`,
`@detectSQLi`, `@unconditionalMatch`, `@validateUtf8Encoding`.

Sixteen compile and evaluate today. `@detectSQLi` and `@detectXSS` parse but
**refuse to compile**, because they need a libinjection classifier and
compiling them to something that never matches would turn four CRS rules into
silent bypasses. CI asserts that the refusal set is exactly those two, so a
newly refused operator fails the build.

The only pure-Rust candidate, `libinjectionrs`, has been audited against the C
original: 1,631 of 162,963 inputs tokenize differently, four divergence classes
are characterised, and differential fuzzing finds a new one every few minutes
once its NUL blind spot is removed. The verdict is **do not adopt yet**, and
the refusal stays. See
[docs/audit-libinjectionrs.md](docs/audit-libinjectionrs.md) for the findings
and how to reproduce them; the fixes and the missing test infrastructure are
contributed upstream in
[saarw/libinjectionrs#1](https://github.com/saarw/libinjectionrs/pull/1).

Known hard parts, called out rather than discovered later: multipart parsing
edge cases, `XML` selection (175 target references in CRS), persistent
collections, and `MATCHED_VARS` semantics.

## License

Licensed under **either**

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), **or**
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. You choose one and comply with that one; you do not need to
satisfy both. This is the Rust ecosystem default, and it is broader than either
license alone: the MIT branch is GPL-compatible at every GPL version, while the
Apache branch carries an express patent grant that some legal reviews require.
Apache-2.0 alone would exclude GPLv2-only consumers; MIT alone would drop the
patent grant.

Contributions are accepted under the same terms, under a DCO sign-off and with
no CLA. See [CONTRIBUTING.md](CONTRIBUTING.md).

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
