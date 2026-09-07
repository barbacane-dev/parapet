import glob, json, os, re, sys

RULES = sys.argv[1]
out = []
op_counts = {}

def logical_lines(text):
    """SecLang continues a directive with a trailing backslash."""
    buf = []
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if line.rstrip().endswith("\\"):
            buf.append(line.rstrip()[:-1])
        else:
            buf.append(line)
            yield "".join(buf)
            buf = []
    if buf:
        yield "".join(buf)

def split_args(line):
    """Split a directive into shell-ish tokens honouring double quotes and \\" escapes."""
    toks, cur, q, i = [], [], False, 0
    while i < len(line):
        c = line[i]
        if q:
            if c == "\\" and i + 1 < len(line) and line[i+1] == '"':
                cur.append('"'); i += 2; continue
            if c == '"':
                q = False; i += 1; continue
            cur.append(c); i += 1; continue
        if c == '"':
            q = True; i += 1; continue
        if c.isspace():
            if cur: toks.append("".join(cur)); cur = []
            i += 1; continue
        cur.append(c); i += 1
    if cur: toks.append("".join(cur))
    return toks

for path in sorted(glob.glob(os.path.join(RULES, "*.conf"))):
    text = open(path, encoding="utf-8").read()
    for line in logical_lines(text):
        st = line.strip()
        if not st.startswith("SecRule "):
            continue
        toks = split_args(st)
        if len(toks) < 3:
            continue
        vars_, operator = toks[1], toks[2]
        neg = operator.startswith("!")
        body = operator[1:] if neg else operator
        m = re.match(r"^@(\w+)\s*(.*)$", body, re.S)
        if m:
            name, arg = m.group(1), m.group(2)
        else:
            name, arg = "rx", body   # bare operator argument defaults to @rx
        op_counts[name] = op_counts.get(name, 0) + 1
        if name != "rx":
            continue
        rid = re.search(r"\bid:(\d+)", st)
        out.append({
            "file": os.path.basename(path),
            "id": rid.group(1) if rid else None,
            "negated": neg,
            "vars": vars_[:80],
            "pattern": arg,
        })

json.dump(out, open(sys.argv[2], "w"), indent=1)
print(f"@rx patterns extracted: {len(out)}")
print(f"unique patterns:        {len(set(p['pattern'] for p in out))}")
print("\noperator frequency across all SecRule directives:")
for k, v in sorted(op_counts.items(), key=lambda kv: -kv[1]):
    print(f"  @{k:<22} {v}")
