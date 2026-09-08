# Audit: `libinjectionrs` as the `@detectSQLi` / `@detectXSS` backend

**Date:** 2026-09-08
**Version audited:** 0.1.1 (crates.io), repository at `saarw/libinjectionrs@597f581`
**Question:** can Parapet depend on this for `@detectSQLi` and `@detectXSS`?
**Answer:** not as-is, but the failure mode is narrower and less dangerous than
the maturity signals suggest, and adopting it with documented gaps is safer
than the status quo. See [Verdict](#verdict).

## Why this needs an audit at all

`@detectSQLi` and `@detectXSS` are the only two operators Parapet refuses to
compile, which costs 4 CRS rules and 30 stages of the regression suite. The
only pure-Rust option is `libinjectionrs`, at 0.1.1 with 16 stars, on a path
where a wrong answer is a bypass. Its own README says:

> A vibe port (AI translation without manually reviewing much of the code) of
> the libinjection library from C to memory-safe Rust. The port was done with
> an original plan created with GPT-5 and then mostly executed with Claude Code.

That candour is to the author's credit and it is also the reason to measure
rather than read.

## What the crate gets right

**Supply chain is small.** Two runtime dependencies, `bitflags` and
`smallvec`. Nothing transitive worth worrying about.

**Panic discipline is enforced, not aspirational.** The workspace denies
`unsafe_code`, `unwrap_used`, `expect_used`, `panic`, `unreachable`,
`unimplemented` and `todo`, and the library contains zero occurrences of any
of them. `arithmetic_side_effects` is warned on.

**Licensing and attribution are clean.** BSD-3-Clause, matching upstream, with
the C library vendored as a submodule.

**The C corpus is genuinely exercised.** 60 tests pass, reading 63 HTML5, 118
folding and 249 token test files from the upstream C repository.

## What the quality claims do not support

**`differential_tests.rs` is not a differential test.** Its own comments say
so: `// Test with our Rust implementation only (since we don't have C
comparison in tests)` and `// we'd need C comparison for real differential
testing`. It runs Rust alone against inputs it assumes should be positive,
samples 20 inputs per file across 10 files per category (300 cases), prints
`Total matches: 281/300 (93.7%)`, and asserts only `assert!(result.total_tests
> 0)`. It cannot fail, and it passes today while reporting 93.7%.

**The real C differential exists only as a fuzz target, with two blind spots.**
`fuzz/fuzz_targets/fuzz_differential_sqli.rs` does compare against the C
library over FFI, and compares `is_injection()` rather than fingerprints, which
is the right choice. But it skips every input containing a NUL byte
(`if data.contains(&0) { return; }`), and it only panics on a divergence when
`data.len() < 1000`, so a divergence on a longer input is detected and
discarded. A WAF receives both.

**There is no CI.** No `.github/workflows`. The claimed hour of differential
fuzzing was a manual, one-off run; the last commit is 2025-09-05.

**`comparison-bin`'s fingerprint comparison is broken.** `match_fingerprint`
is computed only when both sides report an injection and returns `true`
otherwise, with the comment "Both safe, fingerprint doesn't matter". The `else`
branch is also taken when the two sides *disagree*, which is the only case
worth looking at. It reports `match_fingerprint: true` for inputs where the
fingerprints are plainly different.

**The differential tooling does not build out of the box.** The FFI harness
static library has to be built by hand first (`cd ffi-harness && make`), or
`cargo build -p libinjection-comparison` fails at link time.

## Measurements

Reference implementation is the C library itself, vendored at
`libinjection@85e252a`, driven through the crate's own FFI harness. Corpus is
libinjection's own attack vectors and false-positive set (`libinjection-c/data/*.txt`,
47 files) plus every single-line `--INPUT--` section from
`libinjection-c/tests/*.txt`, deduplicated: **162,957 inputs**.

| Check | Inputs | Result |
|---|---|---|
| SQLi verdicts vs C | 162,957 | **7 divergences, all false negatives** |
| SQLi fingerprints, where both flagged | 16,725 | **0 divergences** |
| XSS verdicts vs C | 162,957 | **14 divergences, all false negatives** |
| SQLi verdicts, inputs ≥1000 bytes | 1,200 | 0 divergences |
| Panic sweep, both entry points | 465,836 (931,672 calls) | **0 panics** |

Zero false positives anywhere. Zero panics, including all 65,536 one- and
two-byte inputs, NUL-containing inputs, and 50,000-byte pathological repeats.
The residual panic risk its README names did not materialise.

### The 7 SQLi misses are one bug class

All seven involve multi-word SQL keywords, which libinjection folds into a
single token:

```
1 into outfile 'asd'                    rust=clean  c=injection
'1' into outfile 'asd'                  rust=clean  c=injection
@version into outfile 'asd'             rust=clean  c=injection
-1 LOCK IN SHARE MODE UNION SELECT ...  rust=clean  c=injection
1' IN BOOLEAN MODE) PROCEDURE ANALYSE(EXTRACTVALUE(...))  rust=clean  c=injection
1' IN BOOLEAN MODE) RLIKE (SELECT (CASE WHEN ...))        rust=clean  c=injection
```

Fingerprints pin the mechanism. The multi-word keyword never becomes a `k`
token on the Rust side:

| Input | C | Rust |
|---|---|---|
| `1 into outfile 'asd'` | `1ks` | `sns` |
| `'1' into outfile 'asd'` | `sks` | `s1sns` |
| `@version into outfile 'asd'` | `vks` | `sns` |
| `-1 LOCK IN SHARE MODE UNION SELECT ...` | `1kUEn` | `1nnnn` |
| `1' IN BOOLEAN MODE) PROCEDURE ANALYSE(...)` | `sk)f(` | `snn)f` |
| `1' IN BOOLEAN MODE) RLIKE (SELECT (CASE ...))` | `sk)o(` | `snn)o` |

Rust is not folding `INTO OUTFILE`, `LOCK IN SHARE MODE`, `IN BOOLEAN MODE` or
`PROCEDURE ANALYSE` into keyword tokens, so the fingerprint never reaches the
blacklist. `INTO OUTFILE` is a file-write primitive, so this is not a cosmetic
class.

That fingerprints agree on all 16,725 inputs both engines flag says the
tokenizer is otherwise faithful; the defect is confined to multi-word folding.

### The 14 XSS misses are one bug class

Whitespace or a control byte between an attribute name and its `=`:

```
<img src=x onerror%09="alert(1)">    rust=clean  c=injection
<img src=x onerror%0A="alert(1)">    (also %0B %0C %0D %20 %00)
`"'><img src=xxx:x onerror%00=javascript:alert(1)>
```

This is a standard attribute-separator evasion, and catching it is much of the
point of `detectXSS`.

## Verdict

21 false negatives in 162,957 inputs, zero false positives, zero panics, two
identified bug classes, no CI, one year stale.

Not adoptable as-is. But the decisive comparison is not against a perfect
library, it is against **the status quo, which is refusing the operator
entirely**. A `@detectSQLi` that misses `INTO OUTFILE` still catches the
thousands of vectors it agrees with C on; an operator that refuses to compile
catches nothing and removes 4 CRS rules from the rule set. On that comparison,
adopting with documented gaps is the safer position, provided the gaps are
known rather than inherited blindly.

Recommended order:

1. **Fix the two bug classes.** Both are narrow and localised: multi-word
   keyword folding in `sqli/tokenizer.rs`, attribute-separator handling in
   `xss/html5.rs`. The corpus and harness in this audit verify a fix in
   seconds. Contribute upstream; fork only if that stalls.
2. **Adopt behind a differential gate in Parapet's CI**, the same shape as the
   existing transformation differential: the C library as reference, this
   corpus, and a divergence allowlist with a written reason per entry, so a new
   divergence fails the build. Without that gate, Parapet inherits a
   dependency nobody is testing.
3. **Do not adopt without the gate.** The crate has no CI of its own, so
   Parapet's would be the only thing standing between a future release and a
   silent bypass.

If neither 1 nor 2 is worth the effort, keeping the refusal is defensible: it
costs 30 regression stages and 0.8 points, and it fails loudly rather than
quietly.

## Reproducing this

```bash
git clone https://github.com/saarw/libinjectionrs.git
cd libinjectionrs && git submodule update --init --recursive --depth 1
cd ffi-harness && make CC=clang && cd ..           # not built by cargo
cargo build --release -p libinjection-comparison

python3 <parapet>/crates/parapet-conformance/tools/audit/build_corpus.py \
  libinjection-c corpus.txt corpus_long.txt
./target/release/compare sqli --file corpus.txt --json > sqli.json
./target/release/compare xss  --file corpus.txt --json > xss.json
python3 <parapet>/crates/parapet-conformance/tools/audit/analyse.py sqli.json xss.json
```

The panic sweep is `tools/audit/panic_sweep.rs`, a standalone binary against
the published crate; it is deliberately not a workspace member, so it does not
put `libinjectionrs` in Parapet's dependency graph before the decision is made.
