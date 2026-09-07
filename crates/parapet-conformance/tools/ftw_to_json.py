#!/usr/bin/env python3
"""Convert the CRS regression corpus (FTW YAML) into one JSON file.

Keeps the conformance crate free of a YAML dependency, and makes the corpus a
single artifact the Rust harness can load. Only the fields the harness uses
are carried across; anything else is reported so a schema change is visible
rather than silently dropped.
"""
import json
import os
import sys

import yaml

USED_INPUT = {"dest_addr", "port", "method", "uri", "version", "headers", "data"}
UNSUPPORTED_INPUT = {"encoded_request"}


def main() -> None:
    root, out_path = sys.argv[1], sys.argv[2]
    files = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in sorted(filenames):
            if name.endswith(".yaml"):
                files.append(os.path.join(dirpath, name))
    files.sort()

    tests = []
    skipped = 0
    unknown_input_keys: dict[str, int] = {}
    unknown_output_keys: dict[str, int] = {}

    for path in files:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if not doc or "tests" not in doc:
            continue
        rule_id = doc.get("rule_id")
        for test in doc["tests"] or []:
            for i, stage in enumerate(test.get("stages") or []):
                stage_body = stage.get("stage", stage)
                inp = stage_body.get("input") or {}
                out = stage_body.get("output") or {}

                for key in inp:
                    if key not in USED_INPUT and key not in UNSUPPORTED_INPUT:
                        unknown_input_keys[key] = unknown_input_keys.get(key, 0) + 1
                for key in out:
                    if key not in {"log", "status"}:
                        unknown_output_keys[key] = unknown_output_keys.get(key, 0) + 1

                if any(k in inp for k in UNSUPPORTED_INPUT):
                    skipped += 1
                    continue

                log = out.get("log") or {}
                headers = inp.get("headers") or {}
                data = inp.get("data")
                if isinstance(data, list):
                    data = "\n".join(str(d) for d in data)

                tests.append({
                    "file": os.path.basename(path),
                    "rule_id": rule_id,
                    "test_id": test.get("test_id"),
                    "stage": i,
                    "desc": (test.get("desc") or "")[:120],
                    "method": inp.get("method") or "GET",
                    "uri": inp.get("uri") or "/",
                    "version": inp.get("version") or "HTTP/1.1",
                    "headers": {str(k): str(v) for k, v in headers.items()},
                    "data": data,
                    "expect_ids": log.get("expect_ids") or [],
                    "no_expect_ids": log.get("no_expect_ids") or [],
                    "status": out.get("status"),
                })

    with open(out_path, "w") as fh:
        json.dump(tests, fh)

    print(f"test files      : {len(files)}")
    print(f"stages emitted  : {len(tests)}")
    print(f"stages skipped  : {skipped} (encoded_request, a raw-request form)")
    if unknown_input_keys:
        print(f"unused input keys : {unknown_input_keys}")
    if unknown_output_keys:
        print(f"unused output keys: {unknown_output_keys}")


if __name__ == "__main__":
    main()
