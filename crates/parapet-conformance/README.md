# Conformance

Three checks, in increasing strength. The first two run on every commit; the
third gates releases.

## 1. Compile coverage

Every `@rx` operand in a pinned CRS release must compile.

```bash
curl -sL https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.9.0.tar.gz | tar xz
python3 tools/extract_rx.py coreruleset-4.9.0/rules rx.json
cargo run -p parapet-conformance -- compile rx.json
```

Expected against v4.9.0: 273 unique patterns, 268 compiling as authored, 5
after repair, 0 failing. A non-zero failure count exits non-zero.

## 2. Parse coverage

Every directive in a pinned CRS release must parse, and the directive counts
must match figures measured independently of the parser.

```bash
cargo run -p parapet-conformance -- parse coreruleset-4.9.0/rules crs-4.9.0
```

Expected against v4.9.0: 660 `SecRule`, 7 `SecAction`, 29 `SecMarker`, 1
`SecComponentSignature`, 73 chain starters, 587 rules carrying an `id:`.

The counts matter as much as the zero-error result. A parser that stops
recognising a construct would still report zero errors while returning fewer
rules, and a rule set silently short by 40 rules is a rule set with 40
bypasses. The expectation set turns that into a build failure.

## 3. Operator compile coverage

Every operator in a pinned CRS release must compile, including resolving the
`@pmFromFile` data files off disk.

```bash
cargo run -p parapet-conformance -- operators coreruleset-4.9.0/rules
```

Expected against v4.9.0: 18 distinct operators, 19 data files, 656 of 660
operator instances compiling, and exactly two refusals (`@detectSQLi` and
`@detectXSS`, 4 rules).

The refusal set is itself a gate. A newly refused operator means a rule
silently stopped being enforceable; a refusal disappearing because it got
implemented is fine.

## 4. End to end

The only check that exercises everything at once. Loads `crs-setup.conf.example`
plus every rule file, then runs a request corpus through all five phases.

```bash
cargo run -p parapet-conformance -- run coreruleset-4.9.0/rules
```

Blocking must come from CRS rule 949110 on accumulated anomaly score, the way a
real deployment blocks, not from an individual rule denying. The corpus carries
benign requests too: a false positive is as much a defect as a miss.

Current state: 18 cases, **0 wrong verdicts**, 1 known gap.

Two of the corpus expectations are worth reading, because both were wrong when
first written and looked like engine bugs:

- `rce backtick` expects **allow**. Rule 932131 covers bare backticks and is
  tagged `paranoia-level/2`, so CRS at the default level does not block it.
  Asserting the allow keeps a future change from silently raising the effective
  paranoia level.
- `sqli tautology` is a `known_gap`, attributed to rule 942100 needing
  `@detectSQLi`. Attributed gaps still run and still print; they just do not
  fail the build.

## 5. Transformations against a reference implementation

Transformations decide what an operator actually sees, so a divergence here is
a bypass or a false positive rather than a cosmetic difference. Unit tests only
prove self-consistency, so all 20 are compared against Coraza's outputs over
14,480 cases: hand-picked evasion vectors, every truncation boundary of every
escape syntax, and random metacharacter-heavy byte strings including invalid
UTF-8.

```bash
python3 tools/gen_transform_corpus.py corpus.json
git clone --depth 1 https://github.com/corazawaf/coraza.git /tmp/coraza-ref
cp tools/coraza_probe_test.go /tmp/coraza-ref/internal/transformations/
cd /tmp/coraza-ref && PROBE_IN=.../corpus.json PROBE_OUT=.../reference.json \
  go test ./internal/transformations/ -run TestParapetProbe
cargo run -p parapet-conformance -- transform-diff reference.json
```

Current state: **0 unexpected divergences**, with 939 cases matched by six
documented expectations.

A reference implementation is a reference, not an oracle, so each expectation
is a predicate over the specific input rather than a blanket exemption for a
transformation. A *new* divergence in an already-diverging transformation still
fails the build. The six:

| Transformation | Cases | Why |
|---|---|---|
| `lowercase`, `removeWhitespace`, `utf8toUnicode` | 289 each | The reference decodes runes, so invalid UTF-8 becomes U+FFFD before the transformation runs. SecLang is byte-oriented and a WAF must not rewrite bytes it was asked to inspect. |
| `normalizePathWin` | 41 | The reference adds NTFS Alternate Data Stream and trailing-dot stripping. Sound hardening against a real Windows bypass class, but beyond ModSecurity semantics, which is what CRS is authored against. To settle with the FTW suite. |
| `jsDecode` | 28 | Reference bug: the octal branch fills its digit buffer starting at the backslash, so every `\OOO` escape parses as invalid and decodes to NUL. |
| `normalizePath` | 2 | Reference bug: a trailing slash is re-appended without checking for one, so `/` and `//` both become `//`. |
| `htmlEntityDecode` | 1 | The reference UTF-8 encodes the `&nbsp;` result (`0xc2 0xa0`); ModSecurity emits the single byte `0xa0`. |

The two reference bugs were found by this harness and are worth reporting
upstream. The `jsDecode` one is security-relevant: a CRS rule relying on
`t:jsDecode` to unmask an octal-escaped payload would not see it.

## 6. Differential against Go/RE2

Where the engine repairs a pattern in order to compile it, the repair must not
change what the pattern matches. Go's `regexp` is the reference, because it is
the engine Coraza evaluates `@rx` with and the semantics CRS is authored
against.

```bash
go run tools/re2_verdicts.go corpus.json verdicts_re2.json
```

The corpus combines the CRS regression payloads for the affected rules,
alphabet-biased random strings, and single-edit mutations of known positives.
A corpus is only valid if every pattern under test has both matching and
non-matching inputs: agreement on an all-negative corpus proves nothing.

Last run: 297,129 inputs, 0 disagreements, 1,838 to 6,026 positives per rule.

## 7. CRS regression suite

The release gate, and the only number that decides whether Parapet is
CRS-compatible.

```bash
pip install pyyaml
python3 tools/ftw_to_json.py coreruleset-4.9.0/tests/regression/tests ftw.json
cargo run -p parapet-conformance -- ftw coreruleset-4.9.0/rules ftw.json 91.0
```

Current state: **3,635 of 3,853 stages pass (94.3%)**, 21 skipped
(status-only assertions), 10 not converted (`encoded_request`, a raw-request
form).

The corpus is CRS's own, converted from YAML to JSON in Python so the crate
needs no YAML dependency. It runs in process rather than through `go-ftw`
against a live server: faster, deterministic, and it gives a rule id and a
test label when something fails. The assertions are identical, `expect_ids`
and `no_expect_ids`.

Two things the harness must get right, both learned the hard way:

**The paranoia level.** Stages run with the configuration CRS documents in
`tests/regression/README.md`, injected verbatim as rule 900005 rather than
hand-seeded, so the harness cannot drift from what the corpus assumes. Most of
the corpus exercises rules tagged `paranoia-level/2` and above. Running at the
default level scores 55.2%; running at the documented level scores 91.1%. The
36-point difference was entirely harness configuration, and every one of those
failures looked like an engine bug.

**Implied request headers.** FTW completes a request the way a client would: a
body implies `Content-Type: application/x-www-form-urlencoded` and a
`Content-Length` unless the test sets them. Without that the urlencoded parser
never runs, `ARGS_POST` stays empty, and most of the 2,416 body-carrying
stages fail for a reason that has nothing to do with rules.

**A rising number is not always progress.** An earlier run scored 91.1%
because `REQUEST_BODY` was populated for every content type, so rules matched
raw XML and JSON text by accident. Fixing that dropped the rate to 79.0%,
which was the honest number, and parsing XML and JSON properly brought it to
92.3%. A conformance number is only as good as the semantics underneath it,
and the drop was the useful signal.

**Detection-only, deliberately.** The assertions are about which rules appear
in the log, so a disruptive action that ended the transaction early would hide
later rules and turn a correct engine into a failing one. This means the suite
does not yet verify blocking *decisions*, only rule firing. A future blocking
run is a separate, stricter gate, and the distinction matters: detection-only
conformance says nothing about whether the WAF decides correctly.

### The gate is a ratchet

The suite is not at 100%, so CI enforces a floor rather than perfection. Raise
`FTW_BASELINE` when the rate improves; never lower it. A pass/fail gate at
100% would have to be disabled to be useful, and a gate that is disabled is
not a gate.
