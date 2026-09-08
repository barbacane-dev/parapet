#!/usr/bin/env python3
"""Build the differential corpus for the libinjectionrs audit.

Two outputs. The main corpus is libinjection's own attack vectors and
false-positive set plus every single-line test input, which is the strongest
available ground truth. The long corpus lives entirely in the blind spot of
the upstream differential fuzz target, which discards divergences on inputs of
1000 bytes or more.

Usage: build_corpus.py <libinjection-c-dir> <out-main> <out-long>
"""
import glob
import os
import random
import sys

random.seed(20260908)


def main() -> None:
    c, out_main, out_long = sys.argv[1], sys.argv[2], sys.argv[3]
    lines = []

    # Raw attack vectors and known false positives, one per line.
    for path in sorted(glob.glob(os.path.join(c, "data", "*.txt"))):
        for line in open(path, encoding="utf-8", errors="replace"):
            line = line.rstrip("\r\n")
            if line and not line.startswith("#"):
                lines.append(line)

    # Single-line --INPUT-- sections from the structured tests.
    for path in sorted(glob.glob(os.path.join(c, "tests", "*.txt"))):
        txt = open(path, encoding="utf-8", errors="replace").read().split("\n")
        for i, line in enumerate(txt):
            if line.strip() != "--INPUT--":
                continue
            body = []
            for nxt in txt[i + 1:]:
                if nxt.startswith("--"):
                    break
                body.append(nxt)
            if len(body) == 1 and body[0].strip():
                lines.append(body[0])

    # An embedded NUL cannot cross the C FFI boundary as a CString, so those
    # inputs are covered by panic_sweep.rs instead of here.
    seen, corpus = set(), []
    for line in lines:
        if not line or "\x00" in line or line in seen:
            continue
        seen.add(line)
        corpus.append(line)

    with open(out_main, "w") as fh:
        fh.write("\n".join(corpus) + "\n")
    print(f"corpus lines: {len(corpus)}")

    long_inputs = []
    for base in corpus[:400]:
        pad = "".join(random.choice(" abc0123,;()'\"=-/*") for _ in range(1100))
        long_inputs.append(base + pad)
        long_inputs.append(pad + base)
        long_inputs.append(base * (1000 // max(1, len(base)) + 2))
    with open(out_long, "w") as fh:
        fh.write("\n".join(x.replace("\n", " ") for x in long_inputs) + "\n")
    print(f"long-input corpus: {len(long_inputs)} (all >= 1000 bytes)")


if __name__ == "__main__":
    main()
