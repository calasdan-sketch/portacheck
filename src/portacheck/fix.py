"""Turn findings into reviewable ``git mv`` commands.

portacheck never renames anything itself. ``--format gitmv`` prints a POSIX
shell script you read, edit and run. Every name is written so the script is
safe to display and run: names with anything but plain printable characters
use bash ``$'...'`` quoting with explicit ``\\u`` / ``\\x`` escapes, so a
hostile file name cannot rewrite your terminal or smuggle in a command.
"""
from __future__ import annotations

import re
import shlex
import unicodedata
from collections import Counter
from typing import Dict, Iterable, List, Sequence, Set, Tuple

from .rules import RESERVED, Finding, check_component, mac_nfc, utf16_len, windows_fold

#: codes a rename can repair on its own; everything else is reported as manual
_RENAMEABLE = {"reserved_name", "invalid_char", "trailing_dot", "trailing_space", "invisible_char",
               "not_nfc", "component_too_long", "case_collision", "unicode_collision",
               "short_name_collision"}

_BAD = re.compile(r'[<>:"|?*\\\x00-\x1f]')
_SAFE_PRINTABLE = re.compile(r"^[A-Za-z0-9_@%+=:,./~-]+$")


def sanitize_component(name: str) -> str:
    """A Windows- and macOS-safe spelling of one path component (best effort)."""
    n = "".join(c for c in name if unicodedata.category(c) != "Cf")  # bidi / zero-width
    n = mac_nfc(n)
    n = "".join("_" if ord(c) in range(0xDC80, 0xDD00) else c for c in n)  # raw undecodable bytes
    n = _BAD.sub("_", n)
    n = n.rstrip(" .") or "_"
    cut = len(n)
    for sep in ".:":
        i = n.find(sep)
        if i != -1:
            cut = min(cut, i)
    if n[:cut].rstrip(" ").upper() in RESERVED:
        n = n[:cut].rstrip(" ") + "_" + n[cut:]
    if utf16_len(n) > 200:  # leave room for a de-duplication suffix
        stem, dot, ext = n.rpartition(".")
        if not dot or len(ext) > 20:
            stem, ext = n, ""
        else:
            ext = "." + ext
        while utf16_len(stem + ext) > 200:
            stem = stem[:-1]
        n = stem + ext
    return n


def _with_suffix(name: str, k: int) -> str:
    stem, dot, ext = name.rpartition(".")
    if not dot or not stem:
        return f"{name}_{k}"
    return f"{stem}_{k}.{ext}"


def _ansi_c(s: str) -> str:
    out = []
    for c in s:
        o = ord(c)
        if 0xDC80 <= o <= 0xDCFF:
            out.append(f"\\x{o - 0xDC00:02x}")
        elif c == "\\":
            out.append("\\\\")
        elif c == "'":
            out.append("\\'")
        elif o < 32 or o == 127 or 0x80 <= o < 0xA0 or unicodedata.category(c) in ("Cf", "Cs", "Zl", "Zp"):
            out.append(f"\\u{o:04x}" if o <= 0xFFFF else f"\\U{o:08x}")
        else:
            out.append(c)
    return "$'" + "".join(out) + "'"


def sh_quote(s: str) -> str:
    """Shell-safe, display-safe quoting of an untrusted path."""
    if _SAFE_PRINTABLE.match(s) and not s.startswith("-"):
        return s
    if all(unicodedata.category(c) not in ("Cc", "Cf", "Cs", "Zl", "Zp") for c in s):
        return shlex.quote(s)
    return _ansi_c(s)


def plan_renames(all_paths: Iterable[str], findings: Sequence[Finding]) -> Tuple[List[Tuple[str, str]], List[str]]:
    """(renames, manual notes). Renames are ordered deepest first, each as the
    original full path -> new full path, so a child is moved before its parent."""
    from .scan import _parent  # local: scan imports rules, not fix

    paths = set(all_paths)
    # every folder implied by the index
    dirs: Set[str] = set()
    for p in list(paths):
        q = _parent(p)
        while q:
            dirs.add(q)
            q = _parent(q)
    used: Dict[str, Counter] = {}
    for p in paths | dirs:
        used.setdefault(_parent(p), Counter())[windows_fold(mac_nfc(p.rsplit("/", 1)[-1]))] += 1

    todo: Dict[str, str] = {}  # path -> reason code
    manual: List[str] = []
    # Git metadata names and symlinks need a human: renaming ".git ." to ".git" would be the attack itself
    blocked = {f.path for f in findings if f.code in ("git_dir_alias", "git_meta_alias", "symlink_meta")}
    for f in findings:
        if f.code in _RENAMEABLE:
            if f.code in ("case_collision", "unicode_collision"):
                members = sorted(set(f.paths or (f.path,)))
                for m in members[1:]:  # keep the first spelling, rename the rest
                    todo.setdefault(m, f.code)
            elif f.code == "short_name_collision":
                for m in (f.paths or (f.path,))[1:]:  # the tilde look-alike is the one to rename
                    todo.setdefault(m, f.code)
            else:
                todo.setdefault(f.path, f.code)
        else:
            manual.append(f"{f.code}: {f.path}")

    renames: List[Tuple[str, str]] = []
    for path in sorted(todo, key=lambda p: (-p.count("/"), p)):
        parent, name = _parent(path), path.rsplit("/", 1)[-1]
        if path in blocked:
            manual.append(f"rename by hand (Git metadata name): {path}")
            continue
        new = sanitize_component(name)
        if todo[path] == "short_name_collision":
            new = new.replace("~", "_")
        for _ in range(3):
            if not any(x.severity == "error" for x in check_component(new)):
                break
            new = "_" + new  # never suggest a name that is itself reserved or an alias
        else:
            manual.append(f"no safe automatic name found: {path}")
            continue
        taken = used.setdefault(parent, Counter())
        if new == name and todo[path] not in ("case_collision", "unicode_collision", "short_name_collision"):
            continue
        taken[windows_fold(mac_nfc(name))] -= 1
        cand, k = new, 1
        while taken[windows_fold(mac_nfc(cand))] > 0 or cand == name:
            k += 1
            cand = _with_suffix(new, k)
        taken[windows_fold(mac_nfc(cand))] += 1
        renames.append((path, (parent + "/" if parent else "") + cand))
    return renames, manual


def render_gitmv(paths: Iterable[str], findings: Sequence[Finding]) -> str:
    """A reviewable POSIX shell script of ``git mv`` commands for the repairable findings."""
    renames, manual = plan_renames(paths, findings)
    lines = ["#!/bin/sh",
             "# Generated by portacheck. Review before running; nothing has been renamed yet.",
             "# Names with special characters use bash $'...' quoting: run with bash, in a UTF-8 locale.",
             "# Renames are ordered deepest first. Fix references (imports, docs, CI) separately.",
             "set -eu"]
    if not renames:
        lines.append("# nothing portacheck can fix by renaming")
    for old, new in renames:
        lines.append(f"git mv -- {sh_quote(old)} {sh_quote(new)}")
    for m in sorted(set(manual)):
        lines.append("# manual: " + _comment_safe(m))
    return "\n".join(lines)


def _comment_safe(s: str) -> str:
    from .rules import printable
    return printable(s).replace("\n", " ")
