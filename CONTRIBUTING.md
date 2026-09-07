# Contributing to Parapet

## License and sign-off

Parapet is dual-licensed `MIT OR Apache-2.0`, and contributions are accepted
under those same terms. There is no CLA and no copyright assignment: you keep
the copyright to what you write.

Sign off each commit to certify you have the right to submit it:

```bash
git commit --signoff -m "your message"
```

That adds a `Signed-off-by` line, indicating you agree to the
[Developer Certificate of Origin](https://developercertificate.org/).

## What is most useful

Rule semantics. Parapet's value is being correct about SecLang, and the fastest
way to help is a failing conformance case: a rule, an input, and the verdict
another engine produces.

## Ground rules

**No silent skips.** A construct the engine does not implement must fail
compilation with a clear error. Never ignore an unparsed directive, operator,
transformation or action, and never downgrade one to a no-op. A rule that does
not fire is a bypass, and a bypass that logs nothing is the worst outcome this
codebase can produce.

**No unverified rewrites of rule content.** If the engine transforms a pattern
or a rule to make it work, the transformation is a no-op on inputs that already
work, and it is differential-tested against a reference engine before it lands.
See `crates/parapet/src/regex_compat.rs` for the shape this takes.

**Conformance numbers come from the harness.** Do not put a compatibility claim
in a doc without a check in `crates/parapet-conformance` that produces it.

**No unsafe.** The crate is `#![forbid(unsafe_code)]`. A WAF parsing hostile
input is the wrong place to hand-manage memory.

## Before opening a PR

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test --workspace
```

## Conformance

See [`crates/parapet-conformance/README.md`](crates/parapet-conformance/README.md).
