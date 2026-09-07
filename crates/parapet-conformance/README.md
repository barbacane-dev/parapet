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

## 3. Differential against Go/RE2

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

## 4. CRS regression suite

The release gate. The Core Rule Set ships 322 YAML regression files (about
5,000 cases) driven by [`go-ftw`](https://github.com/coreruleset/go-ftw).

Required for a stable release:

- 100% of the suite for the enabled paranoia level, **in blocking mode**.
  Detection-only conformance says nothing about whether the engine decides
  correctly, so it is not sufficient.
- No rule silently skipped. An unimplemented construct must fail compilation,
  which means a conformance run cannot pass by ignoring rules it cannot parse.

Not yet wired up: needs the parser and phase engine first.
