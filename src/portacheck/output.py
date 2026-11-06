"""Renderers: text, JSON, GitHub annotations, SARIF 2.1.0.

Every path comes from an untrusted repo, so anything printed to a terminal or a
CI log is escaped: control characters, bidi/zero-width format characters and
undecodable bytes become visible ``\\uXXXX`` / ``\\xNN`` escapes.
"""
from __future__ import annotations

import base64
import json
from typing import List, Sequence
from urllib.parse import quote

from .rules import Finding, printable

INFO_URI = "https://github.com/calasdan-sketch/portacheck"

RULES = {
    "reserved_name": "Windows reserved device name (CON, NUL, COM1, ...)",
    "invalid_char": "Character Windows rejects in file names",
    "invalid_encoding": "Path is not valid UTF-8",
    "trailing_space": "Name ends with a space",
    "trailing_dot": "Name ends with a dot",
    "component_too_long": "Path component longer than 255 UTF-16 units",
    "case_collision": "Paths differ only by case",
    "unicode_collision": "Paths differ only by Unicode normalization",
    "invisible_char": "Invisible or bidi format character in name",
    "not_nfc": "Name is not NFC-normalized",
    "path_length": "Path exceeds Windows MAX_PATH when cloned",
}


def safe(s: str, escape_backslash: bool = True) -> str:
    """Make an untrusted string safe to print (see :func:`portacheck.rules.printable`)."""
    return printable(s, escape_backslash)


def raw_b64(s: str) -> str:
    """Base64 of the exact path bytes (undecodable bytes restored), lossless."""
    return base64.b64encode(s.encode("utf-8", "surrogateescape")).decode("ascii")


def _json_safe(s: str) -> str:
    # lone surrogates cannot be encoded as UTF-8 JSON; show the raw bytes instead
    return "".join(f"\\x{ord(c) - 0xDC00:02x}" if 0xDC80 <= ord(c) <= 0xDCFF else c for c in s)


def render_text(findings: Sequence[Finding], strict: bool) -> str:
    lines = [f"{f.severity.upper():5} {f.code:18} {safe(f.path)}: {safe(f.detail, False)}" for f in findings]
    errors = sum(f.severity == "error" for f in findings)
    warns = len(findings) - errors
    verdict = "FAIL" if errors or (strict and warns) else "PASS"
    lines.append(f"\n{errors} error(s), {warns} warning(s) — {verdict}")
    return "\n".join(lines)


def render_json(findings: Sequence[Finding], root: str, scanned: int) -> str:
    errors = sum(f.severity == "error" for f in findings)
    return json.dumps({
        "path": _json_safe(root),
        "scanned": scanned,
        "errors": errors,
        "warnings": len(findings) - errors,
        "findings": [dict({k: _json_safe(v) for k, v in f.as_dict().items()}, path_raw_b64=raw_b64(f.path))
                     for f in findings],
    }, indent=2)


def _gh_escape(s: str, prop: bool = False) -> str:
    s = safe(s, escape_backslash=prop).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if prop:
        s = s.replace(":", "%3A").replace(",", "%2C")
    return s


def render_github(findings: Sequence[Finding]) -> str:
    """GitHub Actions workflow commands: inline annotations on the PR."""
    lines: List[str] = []
    for f in findings:
        level = "error" if f.severity == "error" else "warning"
        lines.append(f"::{level} file={_gh_escape(f.path, True)},title={_gh_escape('portacheck ' + f.code, True)}"
                     f"::{_gh_escape(f.detail)}")
    return "\n".join(lines)


def render_sarif(findings: Sequence[Finding], version: str) -> str:
    """SARIF 2.1.0 for GitHub code scanning and other SARIF viewers."""
    used = sorted({f.code for f in findings} | set(RULES))
    results = []
    for f in findings:
        results.append({
            "ruleId": f.code,
            "level": "error" if f.severity == "error" else "warning",
            "message": {"text": _json_safe(f.detail)},
            "locations": [{"physicalLocation": {"artifactLocation": {
                "uri": quote(f.path.encode("utf-8", "surrogateescape"), safe="/"), "uriBaseId": "%SRCROOT%"}}}],
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "portacheck", "version": version, "informationUri": INFO_URI,
                "rules": [{"id": r, "shortDescription": {"text": RULES.get(r, r)}} for r in used],
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)
