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

from .rules import Finding, path_bytes, printable

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
    "git_dir_alias": "Path component is, or aliases, the .git directory",
    "git_meta_alias": "Alias of .gitmodules/.gitattributes/.gitignore/.mailmap",
    "short_name_collision": "Name equals the 8.3 short name of a sibling",
    "symlink": "Tracked symlink (needs privileges on Windows)",
    "symlink_meta": "Symlink named like Git metadata",
    "symlink_traversal": "Path below a tracked symlink",
    "symlink_escape": "Symlink points outside the repository",
    "symlink_backslash": "Symlink target contains a backslash",
    "component_bytes": "Name longer than 255 UTF-8 bytes (cannot exist on Linux)",
    "path_length_posix": "Path beyond macOS (1024) or Linux (4096) PATH_MAX",
    "confusable_name": "Sibling names that look alike (homoglyphs, ligatures, full-width)",
    "mixed_script": "One word mixes Latin with Cyrillic/Greek look-alikes",
    "os_junk": "Operating-system metadata file (.DS_Store, Thumbs.db, ._*)",
    "submodule_name": ".gitmodules submodule name with '..' (CVE-2018-11235)",
    "submodule_url": ".gitmodules url that Git or ssh reads as an option or command",
    "submodule_path": ".gitmodules path starting with '-'",
    "submodule_update": ".gitmodules update setting that is a '!' command",
    "submodule_config": ".gitmodules that is too large or does not parse",
}

#: --explain: (typical severity, why it matters, how to fix, source). Sources are the ones the README cites.
_MS = "https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file"
_GITC = "https://github.com/git/git/blob/master/path.c"
EXPLAIN = {
    "reserved_name": ("error", "Windows treats CON, PRN, AUX, NUL, COM1-9, LPT1-9 (and a few more) as devices, with any "
                      "extension: the file cannot be created or opened.", "Rename it (CON.txt -> con_notes.txt).", _MS),
    "invalid_char": ("error", "< > : \" | ? * \\ and control characters are rejected in Windows names.",
                     "Replace the character; `--format gitmv` proposes a name.", _MS),
    "invalid_encoding": ("error", "The name is not valid UTF-8, so Git for Windows cannot reproduce it.",
                         "Rename it with valid UTF-8 (git mv with the escaped bytes shown).", _GITC),
    "trailing_space": ("error", "Windows silently drops trailing spaces, so the file 'disappears' or collides.",
                       "Remove the trailing space.", _MS),
    "trailing_dot": ("error", "Windows silently drops trailing dots.", "Remove the trailing dot.", _MS),
    "component_too_long": ("error", "NTFS allows 255 UTF-16 units per name.", "Shorten the name.", _MS),
    "case_collision": ("error", "Two paths that differ only by case are one file on Windows and default macOS; "
                       "a checkout keeps one and silently loses the other.", "Rename one; keep one spelling.", _MS),
    "unicode_collision": ("error", "NFC and NFD spellings look identical; macOS treats them as one name.",
                          "Rename to the NFC spelling and delete the duplicate.", "https://developer.apple.com/library/archive/technotes/tn/tn1150.html#UnicodeSubtleties"),
    "invisible_char": ("warn", "Bidi or zero-width characters make a name display as something else (Trojan Source).",
                       "Remove the character.", "https://trojansource.codes/"),
    "not_nfc": ("warn", "A decomposed name may be treated as a different file by macOS and Linux tools.",
                "Rename to the composed (NFC) form.", "https://unicode.org/reports/tr15/"),
    "path_length": ("warn", "Over MAX_PATH once cloned under a typical Windows folder; fails unless long paths are "
                    "enabled (Git: core.longpaths).", "Shorten folder names or tune --prefix-len.", _MS),
    "git_dir_alias": ("error", "On Windows/macOS this name resolves to the repository's own .git; a checkout through "
                      "it can overwrite hooks and run code (CVE-2014-9390 family).",
                      "Delete or rename it by hand; never `git mv` it to `.git`.", _GITC),
    "git_meta_alias": ("error/warn", "A non-canonical spelling of .gitmodules/.gitattributes/.gitignore/.mailmap "
                       "that Git reads as the real file on case- or alias-insensitive filesystems.",
                       "Delete it, or rename to the canonical name if intended.", _GITC),
    "short_name_collision": ("error", "NTFS gives long names a hidden 8.3 alias; a tracked file named like that "
                             "alias clashes with it.", "Rename the tilde-style file.", _MS),
    "symlink": ("warn", "On Windows a symlink needs Developer Mode/admin plus core.symlinks=true; otherwise Git "
                "writes a small text file.", "Avoid symlinks, or `--disable symlink` if the repo needs them.",
                "https://git-scm.com/docs/git-config"),
    "symlink_meta": ("error", "A symlink named .gitmodules (etc.) redirects what Git reads and writes.",
                     "Remove the link.", _GITC),
    "symlink_traversal": ("error", "A path below a tracked symlink can be written through the link to anywhere "
                          "(CVE-2018-11235 style).", "Remove the link or the path below it.",
                          "https://nvd.nist.gov/vuln/detail/CVE-2018-11235"),
    "symlink_escape": ("warn", "The link points outside the repository or is absolute.", "Use a relative in-repo target.", ""),
    "symlink_backslash": ("warn", "A backslash is a separator on Windows and an ordinary character elsewhere.",
                          "Use forward slashes in link targets.", ""),
    "component_bytes": ("warn", "Linux file systems limit a name to 255 bytes (NAME_MAX), but NTFS counts UTF-16 "
                        "units: a short-looking name of CJK/emoji characters can be too long on Linux. "
                        "macOS/APFS limit not verified here.", "Shorten the name.", "https://man7.org/linux/man-pages/man3/limits.h.0p.html"),
    "path_length_posix": ("warn/error", "macOS's PATH_MAX is 1024 and Linux's 4096 bytes (including the NUL); a "
                          "relative path alone beyond that cannot be created. 4096+ bytes is an error and is kept out "
                          "of the collision checks. macOS value from sys/syslimits.h, not run on macOS here.",
                          "Flatten the folder tree.", "https://man7.org/linux/man-pages/man3/limits.h.0p.html"),
    "confusable_name": ("warn", "Two different files whose names look alike (Cyrillic/Greek letters, ligatures, "
                        "full-width forms): a reviewer cannot tell README.md from R\u0415ADME.md. Uses a small curated "
                        "subset of Unicode confusables.txt, so it is not exhaustive.", "Rename one; ASCII is safest.",
                        "https://www.unicode.org/reports/tr39/"),
    "mixed_script": ("warn", "A single word mixes Latin with Cyrillic/Greek look-alike letters (p\u0430ypal).",
                     "Use one script per word.", "https://www.unicode.org/reports/tr39/"),
    "os_junk": ("warn", "Finder/Explorer metadata committed by accident.", "git rm it and add it to .gitignore.", ""),
    "submodule_name": ("error", "git builds .git/modules/<name> from the name; '..' writes outside .git/modules and "
                       "can plant a hook (CVE-2018-11235). Git's own fsck rejects it (gitmodulesName).",
                       "Delete the .gitmodules entry.", "https://nvd.nist.gov/vuln/detail/CVE-2018-11235"),
    "submodule_url": ("error/warn", "A url starting with '-' is read as an option (CVE-2017-1000117); an encoded "
                      "newline can inject into credential helpers (CVE-2020-11008); ext:: runs a command (disabled "
                      "by default).", "Use a normal https:// or ssh:// url.",
                      "https://nvd.nist.gov/vuln/detail/CVE-2017-1000117"),
    "submodule_path": ("error", "A path starting with '-' can be read as an option.", "Use a normal path.", ""),
    "submodule_update": ("error", "update = !command would run a command taken from .gitmodules; Git's fsck rejects "
                         "it (gitmodulesUpdate).", "Remove the setting.", ""),
    "submodule_config": ("error/warn", ".gitmodules over 1 MiB (Git's fsck refuses it) or a line Git cannot parse.",
                         "Repair the file.", ""),
}


def explain(code: str) -> str:
    sev, why, fix, src = EXPLAIN[code]
    return (f"{code} ({sev}): {RULES[code]}\n\nWhy: {why}\nFix: {fix}" + (f"\nSource: {src}" if src else "") + "\n")


def safe(s: str, escape_backslash: bool = True) -> str:
    """Make an untrusted string safe to print (see :func:`portacheck.rules.printable`)."""
    return printable(s, escape_backslash)


def raw_b64(s: str) -> str:
    """Base64 of the exact path bytes (undecodable bytes restored), lossless."""
    return base64.b64encode(path_bytes(s)).decode("ascii")


def _json_safe(s: str) -> str:
    # lone surrogates cannot be encoded as UTF-8 JSON; show the raw bytes instead
    return "".join(f"\\x{ord(c) - 0xDC00:02x}" if 0xDC80 <= ord(c) <= 0xDCFF else c for c in s)


def clip(s: str, limit: int = 600) -> str:
    """Shorten a very long path for a human-readable log (JSON, SARIF and baselines keep the full text)."""
    return s if len(s) <= limit else f"{s[:limit // 2]}...[{len(s) - limit} more chars]...{s[-limit // 2:]}"


def render_text(findings: Sequence[Finding], strict: bool) -> str:
    lines = [f"{f.severity.upper():5} {f.code:18} {safe(clip(f.path))}: {safe(clip(f.detail, 1500), False)}"
             for f in findings]
    errors = sum(f.severity == "error" for f in findings)
    warns = len(findings) - errors
    verdict = "FAIL" if errors or (strict and warns) else "PASS"
    lines.append(f"\n{errors} error(s), {warns} warning(s) — {verdict}")
    if len(findings) > 1:
        counts: dict = {}
        for f in findings:
            counts[f.code] = counts.get(f.code, 0) + 1
        lines.append("by code: " + ", ".join(f"{c} {n}" for c, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))))
    return "\n".join(lines)


def _md_cell(s: str) -> str:
    return safe(clip(s, 300)).replace("|", "\\|").replace("`", "\\u0060").replace("\n", " ").replace("<", "&lt;")


def render_markdown(findings: Sequence[Finding], scanned: int, strict: bool, limit: int = 100) -> str:
    """A table for ``$GITHUB_STEP_SUMMARY`` or a PR comment (first ``limit`` findings)."""
    errors = sum(f.severity == "error" for f in findings)
    warns = len(findings) - errors
    verdict = "FAIL" if errors or (strict and warns) else "PASS"
    out = [f"### portacheck: {verdict}", "",
           f"{errors} error(s), {warns} warning(s) in {scanned} path(s).", ""]
    if findings:
        out += ["| severity | code | path | detail |", "|---|---|---|---|"]
        for f in findings[:limit]:
            out.append(f"| {f.severity} | `{f.code}` | `{_md_cell(f.path)}` | {_md_cell(f.detail)} |")
        if len(findings) > limit:
            out.append(f"\n...and {len(findings) - limit} more (use `--format json` for all of them).")
    return "\n".join(out)


def render_json(findings: Sequence[Finding], root: str, scanned: int) -> str:
    errors = sum(f.severity == "error" for f in findings)
    return json.dumps({
        "path": _json_safe(root),
        "scanned": scanned,
        "errors": errors,
        "warnings": len(findings) - errors,
        "findings": [dict({k: ([_json_safe(x) for x in v] if isinstance(v, list) else _json_safe(v))
                           for k, v in f.as_dict().items()}, path_raw_b64=raw_b64(f.path))
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
        lines.append(f"::{level} file={_gh_escape(clip(f.path), True)},title={_gh_escape('portacheck ' + f.code, True)}"
                     f"::{_gh_escape(clip(f.detail, 1500))}")
    return "\n".join(lines)


def _sarif_rule(code: str) -> dict:
    rule = {"id": code, "shortDescription": {"text": RULES.get(code, code)}}
    if code in EXPLAIN:
        _sev, why, fix, src = EXPLAIN[code]
        rule["help"] = {"text": f"{why} Fix: {fix}"}
        if src:
            rule["helpUri"] = src
    return rule


def render_sarif(findings: Sequence[Finding], version: str) -> str:
    """SARIF 2.1.0 for GitHub code scanning and other SARIF viewers."""
    used = sorted({f.code for f in findings} | set(RULES))
    from .baseline import fingerprint

    def loc(p: str) -> dict:
        return {"physicalLocation": {"artifactLocation": {
            "uri": quote(path_bytes(p), safe="/"), "uriBaseId": "%SRCROOT%"}}}

    results = []
    for f in findings:
        res = {
            "ruleId": f.code,
            "level": "error" if f.severity == "error" else "warning",
            "message": {"text": _json_safe(f.detail)},
            "locations": [loc(f.path)],
            # stable identity so code scanning tracks a finding across commits even if its wording changes
            "partialFingerprints": {"portacheck/v1": fingerprint(f)},
        }
        if len(f.paths) > 1:
            res["relatedLocations"] = [dict(loc(p), id=i) for i, p in enumerate(f.paths[1:])]
        results.append(res)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "portacheck", "version": version, "informationUri": INFO_URI,
                "rules": [_sarif_rule(r) for r in used],
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)
