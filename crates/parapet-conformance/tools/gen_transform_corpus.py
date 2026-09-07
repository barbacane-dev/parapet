#!/usr/bin/env python3
"""Generate the transformation differential corpus.

Two halves. Hand-picked vectors cover real evasion shapes (encoded payloads,
inline comments, shell obfuscation, traversal) and every truncation boundary
of every escape syntax, because that is where index arithmetic goes wrong.
Random byte strings over a metacharacter-heavy alphabet, including invalid
UTF-8, cover what nobody thought to write down.
"""
import json
import random
import sys

random.seed(20260907)

NAMES = [
    "none", "base64Decode", "cmdLine", "compressWhitespace", "cssDecode",
    "escapeSeqDecode", "hexEncode", "htmlEntityDecode", "jsDecode", "length",
    "lowercase", "normalizePath", "normalizePathWin", "removeCommentsChar",
    "removeNulls", "removeWhitespace", "replaceComments", "sha1",
    "urlDecodeUni", "utf8toUnicode",
]

SEEDS = [
    "", " ", "  ", "\t\n\r\x0b\x0c", "\x00", "a\x00b",
    "SELECT", "SeLeCt", "select",
    # Percent and IIS-style unicode encoding, with every truncation.
    "%3Cscript%3E", "%u003c", "%uff1c", "%uFF5E", "%zz", "%", "%u", "%u12",
    "%u123", "%uggggg", "a+b", "+", "%2b", "%%3c", "%3", "%c0%ae",
    "%252e%252e%252f",
    # HTML entities, named and numeric, terminated and not.
    "&lt;", "&lt", "&#60;", "&#x3c;", "&#X3C", "&#;", "&#", "&#x", "&",
    "&&amp;", "&nbsp;", "&unknown;", "&quot",
    # Backslash escapes: hex, unicode, extended unicode, octal, single char.
    "\\x3c", "\\x3", "\\x", "\\u0041", "\\u00", "\\u{41}", "\\u{}",
    "\\u{0ff1c}", "\\u{fffffff}", "\\101", "\\1", "\\8", "\\0", "\\", "\\\\",
    "\\n\\t\\v\\a\\b\\f\\r", "\\S\\E\\L\\E\\C\\T", "\\?", "\\'",
    # CSS escapes and their whitespace terminator.
    "\\3c script", "\\3cscript", "\\00003c", "\\65 xpression", "\\e", "\\z",
    "\\ ", "\\\n",
    # Comment syntaxes, including unterminated.
    "/*x*/", "/*", "*/", "a/**/b", "UN/*x*/ION", "select/*rest", "<!--x-->",
    "-->", "--", "#", "a--b", "a#b", "<!--", "<!-",
    # Shell obfuscation.
    "/bin/cat /etc/passwd", "cat /etc", "nc (", 'n"e"t', "c^m^d", "pin\\g",
    "a,b;c", "WGET", "  ,  ;  ",
    # Path traversal, absolute and relative, with trailing separators.
    "/a/b/../c", "/a/./b", "/a//b", "a/b/../../c", "/../etc/passwd",
    "../etc/passwd", "/a/b/", "/", ".", "./", "..", "../", "//", "/.",
    "\\a\\b\\..\\c", "..\\..\\windows\\system32", "C:\\Windows",
    # Base64, valid, wrapped, padded and truncated.
    "PHNjcmlwdD4=", "PHNjcmlwdD", "PHNj\ncmlw dD4=", "=", "====", "!!!!",
    "QQ", "Q",
    # Non-ASCII and full-width.
    "abc", "a" * 100, "\u20ac", "a\u20acb", "\uff1c", "\u2018quoted\u2019",
    "union    select", "a \t\n  b", "  leading", "trailing  ",
]

ALPHABET = list(b'\\%&#/*-<>;,^"\' \t\n\r0123456789abcdefABCDEFuUxX{}.') + [
    0x00, 0x80, 0xff, 0xc0, 0xfe
]


def main() -> None:
    randoms = []
    for _ in range(600):
        n = random.randint(0, 18)
        randoms.append(bytes(random.choice(ALPHABET) for _ in range(n)))

    cases = []
    for name in NAMES:
        for seed in SEEDS:
            cases.append({
                "name": name,
                "input": seed.encode("utf-8", "surrogatepass").hex(),
            })
        for blob in randoms:
            cases.append({"name": name, "input": blob.hex()})

    with open(sys.argv[1], "w") as fh:
        json.dump(cases, fh)
    print(f"transformations: {len(NAMES)}")
    print(f"inputs each:     {len(SEEDS) + len(randoms)}")
    print(f"total cases:     {len(cases)}")


if __name__ == "__main__":
    main()
