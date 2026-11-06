"""Collect portability findings from a directory walk, the git index, or a path list."""
from __future__ import annotations

import os
import subprocess
import unicodedata
from typing import Callable, Dict, Iterable, List, Sequence, Set

from .rules import Finding, check_component, utf16_len, windows_fold

DEFAULT_SKIP = (".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache")

#: Assumed length of the Windows directory a repo is cloned into, *including*
#: the trailing backslash, e.g. ``C:\Users\jane.doe\source\repos\project\``
#: (44 chars). Override with ``prefix_len`` / ``--prefix-len``.
DEFAULT_PREFIX_LEN = 50

#: Windows MAX_PATH. It counts the terminating NUL, so 259 visible chars is
#: the longest path that works without long-path support.
DEFAULT_MAX_PATH = 260


class GitError(RuntimeError):
    """Raised when the git index cannot be read (no git, not a repo, ...)."""


def _parent(rel: str) -> str:
    return rel.rsplit("/", 1)[0] if "/" in rel else ""


def with_parents(rel_paths: Iterable[str]) -> List[str]:
    """Return the paths plus every parent directory they imply, de-duplicated."""
    seen: Dict[str, None] = {}
    for rel in rel_paths:
        while rel.startswith("./"):
            rel = rel[2:]
        parts = [p for p in rel.split("/") if p and p != "."]
        if not parts:
            continue
        for i in range(1, len(parts) + 1):
            seen.setdefault("/".join(parts[:i]), None)
    return list(seen)


def _collisions(rel_paths: Iterable[str], key: Callable[[str], str], code: str,
                why: str, skip_if: Callable[[List[str]], bool] = lambda g: False,
                show: Callable[[str], str] = str) -> List[Finding]:
    groups: Dict[str, Set[str]] = {}
    for rel in rel_paths:
        groups.setdefault(key(rel), set()).add(rel)
    colliding = {k for k, v in groups.items() if len(v) > 1}
    out: List[Finding] = []
    for k, members in groups.items():
        if k not in colliding:
            continue
        originals = sorted(members)
        # Report only the shallowest clash: if the parent directories already
        # collide, every child would repeat the same problem.
        if key(_parent(originals[0])) in colliding and _parent(originals[0]):
            continue
        if skip_if(originals):
            continue
        out.append(Finding("error", code, originals[0], why + ": " + ", ".join(map(show, originals))))
    out.sort(key=lambda f: f.path)
    return out


def case_collisions(rel_paths: Iterable[str]) -> List[Finding]:
    """Paths that are distinct on Linux but the same file on Windows (NTFS).

    Pure — fed any iterable of relative paths, so the logic is testable even on
    case-insensitive filesystems that cannot physically hold both names. Pass
    directories too (see :func:`with_parents`) to catch ``Src/`` vs ``src/``.
    """
    return _collisions(list(rel_paths), windows_fold, "case_collision",
                       "paths differ only by case and cannot coexist on Windows")


def _nfc(s: str) -> str:
    return unicodedata.normalize("NFC", s)


def unicode_collisions(rel_paths: Iterable[str]) -> List[Finding]:
    """Paths that only differ by Unicode normalization (NFC vs NFD), optionally
    combined with case. macOS filesystems treat them as one file."""
    paths = list(rel_paths)
    # skip groups that are already plain case collisions on Windows
    return _collisions(paths, lambda p: windows_fold(_nfc(p)), "unicode_collision",
                       "paths differ only by Unicode normalization and are the same file on macOS",
                       skip_if=lambda g: len({windows_fold(p) for p in g}) == 1,
                       show=ascii)  # escaped, or NFC and NFD forms look identical


def _length_findings(rel_paths: Sequence[str], max_path: int, prefix_len: int) -> List[Finding]:
    over: Dict[str, int] = {}
    for rel in rel_paths:
        total = prefix_len + utf16_len(rel)
        if total >= max_path:
            over[rel] = total
    # the shallowest long path is the actionable one; count what sits inside it
    # (O(n * depth): walk up from each long path to its shallowest long ancestor)
    inside_count: Dict[str, int] = {}
    for rel in over:
        top, p = rel, _parent(rel)
        while p and p in over:
            top, p = p, _parent(p)
        if top != rel:
            inside_count[top] = inside_count.get(top, 0) + 1
    out: List[Finding] = []
    for rel, total in over.items():
        if _parent(rel) in over:
            continue
        inside = inside_count.get(rel, 0)
        extra = f" (+{inside} path(s) inside it)" if inside else ""
        out.append(Finding(
            "warn", "path_length", rel,
            f"about {total} chars once cloned under a {prefix_len}-char Windows folder "
            f"(limit {max_path - 1}){extra}; fails where long paths are not enabled "
            "(Git for Windows core.longpaths is off by default)"))
    return out


def scan_paths(
    rel_paths: Iterable[str],
    max_path: int = DEFAULT_MAX_PATH,
    prefix_len: int = DEFAULT_PREFIX_LEN,
) -> List[Finding]:
    """Check '/'-separated repo-relative paths. Pure: no filesystem access.

    Parent directories are derived automatically, so a plain file list (git
    index, ``git diff --name-only``) is enough.
    """
    paths = with_parents(rel_paths)
    findings: List[Finding] = []
    for rel in paths:
        findings.extend(check_component(rel.rsplit("/", 1)[-1], where=rel))
    findings.extend(_length_findings(paths, max_path, prefix_len))
    findings.extend(case_collisions(paths))
    findings.extend(unicode_collisions(paths))
    findings.sort(key=lambda f: (f.severity != "error", f.code, f.path))
    return findings


def walk_paths(root: str, skip: Sequence[str] = DEFAULT_SKIP, follow_symlinks: bool = False) -> List[str]:
    """Every file and directory under ``root`` as '/'-separated relative paths."""
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in list(dirnames) + list(filenames):
            out.append(os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/"))
    return out


def git_paths(root: str, timeout: float = 120.0) -> List[str]:
    """Tracked + staged paths from the git index under ``root`` (repo-relative).

    Reads the index, not the disk, so it sees exactly what a Windows clone gets
    — including paths your OS could never create. Raises :class:`GitError`.
    """
    cmd = ["git", "-C", root, "ls-files", "-z", "--cached", "--full-name"]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False)
    except FileNotFoundError as e:
        raise GitError("git is not installed or not on PATH") from e
    except subprocess.TimeoutExpired as e:
        raise GitError(f"git ls-files timed out after {timeout:g}s") from e
    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", "replace").strip() or f"exit {proc.returncode}"
        raise GitError(f"git ls-files failed: {msg}")
    return decode_nul_list(proc.stdout)


def decode_nul_list(data: bytes) -> List[str]:
    """Split NUL-separated raw path bytes. Invalid UTF-8 survives as surrogate
    escapes, which :func:`check_component` reports as ``invalid_encoding``."""
    return [p.decode("utf-8", "surrogateescape") for p in data.split(b"\0") if p]


def scan_tree(
    root: str,
    max_path: int = DEFAULT_MAX_PATH,
    skip: Sequence[str] = DEFAULT_SKIP,
    follow_symlinks: bool = False,
    prefix_len: int = DEFAULT_PREFIX_LEN,
) -> List[Finding]:
    """Scan the directory ``root`` for Windows portability hazards.

    * per-component name rules (reserved names, invalid characters, trailing
      dot/space, over-long components, invisible characters, non-NFC names)
    * case-insensitive and Unicode-normalization collisions anywhere in the tree
    * path length as it would be on Windows: ``prefix_len`` + repo-relative path
      (warn — the long-path feature can mitigate it, but plenty of tooling breaks)
    """
    return scan_paths(walk_paths(root, skip, follow_symlinks), max_path=max_path, prefix_len=prefix_len)
