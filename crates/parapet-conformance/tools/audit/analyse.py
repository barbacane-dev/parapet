#!/usr/bin/env python3
"""Analyse comparison-bin output for the libinjectionrs audit.

Recomputes fingerprint agreement rather than trusting the tool's own
`match_fingerprint`, which is only evaluated when both engines report an
injection and returns true otherwise, so it reads as agreement on exactly the
divergent inputs.

Usage: analyse.py <sqli.json> [xss.json]
"""
import json
import sys


def analyse_sqli(path: str) -> int:
    rows = json.load(open(path))
    diverged = [r for r in rows if not r["match_result"]]
    both = [r for r in rows
            if r["rust_result"]["is_injection"] and r["c_result"]["is_injection"]]
    fp_diff = [r for r in both
               if (r["rust_result"].get("fingerprint") or "") != (r["c_result"].get("fingerprint") or "")]

    print(f"SQLi inputs compared        : {len(rows)}")
    print(f"  verdict divergences       : {len(diverged)}")
    print(f"  both flagged              : {len(both)}")
    print(f"  fingerprint divergences   : {len(fp_diff)}  (recomputed, not the tool's field)")
    for r in diverged:
        direction = "FALSE NEGATIVE" if r["c_result"]["is_injection"] else "false positive"
        print(f"    {direction}  rust_fp={r['rust_result'].get('fingerprint')!r} "
              f"c_fp={r['c_result'].get('fingerprint')!r}  {r['input'][:80]!r}")
    return len(diverged)


def analyse_xss(path: str) -> int:
    rows = json.load(open(path))
    diverged = [r for r in rows if not r["matches"]]
    fn = [r for r in diverged if r["c_result"] and not r["rust_result"]]
    print(f"\nXSS inputs compared         : {len(rows)}")
    print(f"  verdict divergences       : {len(diverged)}")
    print(f"  of those, false negatives : {len(fn)}")
    for r in diverged:
        direction = "FALSE NEGATIVE" if r["c_result"] else "false positive"
        print(f"    {direction}  {r['input'][:80]!r}")
    return len(diverged)


if __name__ == "__main__":
    total = analyse_sqli(sys.argv[1])
    if len(sys.argv) > 2:
        total += analyse_xss(sys.argv[2])
    print(f"\ntotal divergences: {total}")
    sys.exit(0 if total == 0 else 1)
