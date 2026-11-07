"""Checks on file *contents* that change how Git treats paths: ``.gitmodules``.

A repository you clone can carry a ``.gitmodules`` file whose submodule *names*,
*urls* and *update* settings are used by ``git submodule`` to build file paths
and to run commands (CVE-2018-11235: a name with ``..``; CVE-2017-1000117: a
url starting with ``-``; CVE-2020-11008: a url with an encoded newline). Git
itself refuses these in ``git fsck``/``receive.fsckObjects`` (``gitmodulesName``,
``gitmodulesUrl``, ``gitmodulesUpdate`` ...); portacheck reports them before
you clone. The tests compare every rule below with a real ``git fsck``.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from .rules import Finding, show_name

#: git's fsck rejects a .gitmodules larger than this (gitmodulesLarge)
GITMODULES_MAX = 1024 * 1024

_SECTION = re.compile(r'\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\\n]|\\.)*)")?\s*\](.*)$', re.S)
_KEY = re.compile(r"[A-Za-z][A-Za-z0-9-]*")
_ESC = {"n": "\n", "t": "\t", "b": "\b", "\\": "\\", '"': '"'}


def _unescape_name(raw: str) -> str:
    return re.sub(r"\\(.)", lambda m: m.group(1), raw)


def _value(raw: str) -> Optional[str]:
    """Value of ``key = value`` the way git-config reads it (quotes, escapes, ``#``/``;`` comments).
    None when the line is malformed (e.g. an unterminated quote or unknown escape)."""
    out: List[str] = []
    quoted = False
    i = 0
    raw = raw.strip()
    while i < len(raw):
        c = raw[i]
        if c == "\\":
            if i + 1 >= len(raw) or raw[i + 1] not in _ESC:
                return None
            out.append(_ESC[raw[i + 1]])
            i += 2
            continue
        if c == '"':
            quoted = not quoted
        elif not quoted and c in "#;":
            break
        else:
            out.append(c)
        i += 1
    if quoted:
        return None
    return "".join(out).rstrip(" \t")


def parse_gitmodules(text: str) -> Tuple[List[Tuple[str, str, str]], List[int]]:
    """([(submodule name, key, value), ...], [line numbers git would not parse])."""
    entries: List[Tuple[str, str, str]] = []
    bad: List[int] = []
    section: Optional[str] = None  # submodule name, or "" for another section
    # join backslash-newline continuations, remembering the first line number
    lines: List[Tuple[int, str]] = []
    pending: Optional[Tuple[int, str]] = None
    for no, line in enumerate(text.replace("\r\n", "\n").split("\n"), 1):
        if pending:
            line = pending[1] + line
            no = pending[0]
            pending = None
        if line.endswith("\\") and not line.endswith("\\\\"):
            pending = (no, line[:-1])
            continue
        lines.append((no, line))
    for no, line in lines:
        s = line.strip()
        while s and not s.startswith(("#", ";")):
            if s.startswith("["):
                m = _SECTION.match(s)
                if not m:
                    bad.append(no)
                    break
                base, sub, rest = m.group(1), m.group(2), m.group(3).strip()
                if base.lower() == "submodule" and sub is not None:
                    section = _unescape_name(sub)
                elif base.lower().startswith("submodule.") and sub is None:
                    section = base[len("submodule."):].lower()  # legacy [submodule.name]: lowercased
                else:
                    section = ""
                s = rest
                continue
            k, eq, v = s.partition("=")
            k = k.strip()
            if not _KEY.fullmatch(k):
                bad.append(no)
                break
            val = "true" if not eq else _value(v)
            if val is None:
                bad.append(no)
                break
            if section:
                entries.append((section, k.lower(), val))
            break
    return entries, bad


def _components(s: str) -> List[str]:
    return re.split(r"[/\\]", s)


def gitmodules_findings(data: bytes, path: str = ".gitmodules") -> List[Finding]:
    """Hazards in the bytes of a ``.gitmodules`` file (see the module docstring)."""
    out: List[Finding] = []
    if len(data) > GITMODULES_MAX:
        return [Finding("error", "submodule_config", path,
                        f".gitmodules is {len(data)} bytes; Git's fsck rejects it above {GITMODULES_MAX} (gitmodulesLarge)",
                        ident="large")]
    text = data.decode("utf-8", "replace")
    if text.startswith("\ufeff"):  # Git's config reader skips a UTF-8 byte-order mark
        text = text[1:]
    entries, bad = parse_gitmodules(text)
    for no in bad[:5]:
        out.append(Finding("warn", "submodule_config", path,
                           f".gitmodules line {no} does not parse as a Git config line; Git may refuse the whole file",
                           ident=f"line{no}"))
    for name, key, val in entries:
        who = show_name(name)
        if key == "name":  # pragma: no cover - not a git key
            continue
        if ".." in _components(name):
            out.append(Finding("error", "submodule_name", path,
                               f"submodule name {who} contains a '..' component: Git builds .git/modules/<name> from it, "
                               "so it can write outside .git/modules (CVE-2018-11235)", ident=name))
        if key == "url":
            low = val.lower()
            if val.startswith("-"):
                out.append(Finding("error", "submodule_url", path,
                                   f"url of {who} starts with '-': Git/ssh would read it as an option "
                                   "(CVE-2017-1000117)", ident=name + "\0url"))
            elif "%0a" in low or "%0d" in low or "\n" in val or "\r" in val:
                out.append(Finding("error", "submodule_url", path,
                                   f"url of {who} contains a newline (CVE-2020-11008 style "
                                   "credential-helper injection)", ident=name + "\0url"))
            elif low.startswith("ext::"):
                out.append(Finding("warn", "submodule_url", path,
                                   f"url of {who} uses the ext:: transport, which runs a command; Git disables it "
                                   "unless protocol.ext.allow is set", ident=name + "\0url"))
        elif key == "path" and val.startswith("-"):
            out.append(Finding("error", "submodule_path", path,
                               f"path of {who} starts with '-' and can be read as a command-line option",
                               ident=name + "\0path"))
        elif key == "update" and val.startswith("!"):
            out.append(Finding("error", "submodule_update", path,
                               f"update of {who} is a '!' command: Git refuses to take a command from .gitmodules "
                               "(gitmodulesUpdate)", ident=name + "\0update"))
    return out
