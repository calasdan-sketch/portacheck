"""Collect portability findings from a directory walk, the git index, or a path list."""
from __future__ import annotations

import posixpath
import re
import os
import subprocess
from collections import Counter
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .rules import (Finding, check_component, dotgit_kind, mac_nfc, printable, show_name,
                    utf16_len, windows_fold)

DEFAULT_SKIP = (".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache")

#: Assumed length of the Windows directory a repo is cloned into, *including*
#: the trailing backslash, e.g. ``C:\Users\jane.doe\source\repos\project\``
#: (39 chars). Override with ``prefix_len`` / ``--prefix-len``.
DEFAULT_PREFIX_LEN = 50

#: Windows MAX_PATH. It counts the terminating NUL, so 259 visible chars is
#: the longest path that works without long-path support.
DEFAULT_MAX_PATH = 260

#: Folders must leave room for an 8.3 file name: MAX_PATH - 12 = 248.
DIR_RESERVE = 12


class GitError(RuntimeError):
    """Raised when the git index cannot be read (no git, not a repo, ...)."""


def _parent(rel: str) -> str:
    return rel.rsplit("/", 1)[0] if "/" in rel else ""


def with_parents(rel_paths: Iterable[str]) -> List[str]:
    """Return the paths plus every parent directory they imply, de-duplicated."""
    return _tree(rel_paths)[0]


def _tree(rel_paths: Iterable[str]) -> Tuple[List[str], Dict[str, List[str]]]:
    """(paths with parents, folder -> names directly inside it). One pass,
    O(unique paths): climbing stops at the first parent already seen."""
    seen: Set[str] = set()
    out: List[str] = []
    by_dir: Dict[str, List[str]] = {"": []}

    def ensure_dir(d: str) -> None:
        if d in by_dir:
            return
        chain = []
        while d not in by_dir:
            by_dir[d] = []
            chain.append(d)
            i = d.rfind("/")
            d = d[:i] if i >= 0 else ""
        for dd in reversed(chain):  # shallowest first
            if dd not in seen:  # (a path may be listed as a file and as a parent)
                seen.add(dd)
                out.append(dd)
                i = dd.rfind("/")
                by_dir[dd[:i] if i >= 0 else ""].append(dd[i + 1:])

    for rel in rel_paths:
        if not rel or rel in seen:
            continue
        if ("//" in rel or "/./" in rel or rel[:1] in ("/", ".") and (rel[:2] in ("./", "/") or rel == ".")
                or rel[-1:] == "/" or rel[-2:] == "/."):
            while rel.startswith("./"):
                rel = rel[2:]
            rel = "/".join(p for p in rel.split("/") if p and p != ".")
            if not rel or rel in seen:
                continue
        i = rel.rfind("/")
        parent = rel[:i] if i >= 0 else ""
        ensure_dir(parent)
        seen.add(rel)
        out.append(rel)
        by_dir[parent].append(rel[i + 1:])
    if not by_dir[""]:
        del by_dir[""]
    return out, by_dir


def _collisions(by_dir: Dict[str, List[str]], key: Callable[[str], str], code: str,
                why: str, skip_if: Callable[[List[str]], bool] = lambda g: False,
                show: Callable[[str], str] = str) -> List[Finding]:
    """Siblings (same folder) whose names are the same under ``key``.

    Two paths only collide in place when they share the exact parent; a clash
    between *different* parents (``Src/`` vs ``src/``) is reported once, at the
    folder, so grouping per folder on the last component is exact, and much
    cheaper than folding every full path.
    """
    out: List[Finding] = []
    for parent, members in by_dir.items():
        if len(members) < 2:
            continue
        keys = [key(m) for m in members]
        if len(set(keys)) == len(keys):
            continue
        groups: Dict[str, List[str]] = {}
        for k, m in zip(keys, members):
            groups.setdefault(k, []).append(m)
        for sub in groups.values():
            if len(sub) < 2:
                continue
            originals = sorted(parent + "/" + n if parent else n for n in sub)
            if skip_if(originals):
                continue
            out.append(Finding("error", code, originals[0], why + ": " + ", ".join(map(show, originals)),
                               tuple(originals)))
    out.sort(key=lambda f: f.path)
    return out


def case_collisions(rel_paths: Iterable[str]) -> List[Finding]:
    """Paths that are distinct on Linux but the same file on Windows (NTFS).

    Pure — fed any iterable of relative paths, so the logic is testable even on
    case-insensitive filesystems that cannot physically hold both names. Parent
    directories are derived automatically, so ``Src/`` vs ``src/`` is caught.
    """
    return _collisions(_tree(rel_paths)[1], windows_fold, "case_collision",
                       "paths differ only by case and cannot coexist on Windows",
                       show=printable)


def _ascii_show(s: str) -> str:
    """Unambiguous ASCII form: non-ASCII as \\uXXXX, raw bytes as \\xNN."""
    out = []
    for c in s:
        o = ord(c)
        if 0xDC80 <= o <= 0xDCFF:
            out.append(f"\\x{o - 0xDC00:02x}")
        elif o > 0xFFFF:
            out.append(f"\\U{o:08x}")
        elif o > 126 or o < 32:
            out.append(f"\\u{o:04x}")
        elif c in "\\'":
            out.append("\\" + c)
        else:
            out.append(c)
    return "'" + "".join(out) + "'"


def unicode_collisions(rel_paths: Iterable[str]) -> List[Finding]:
    """Paths that only differ by Unicode normalization (NFC vs NFD), optionally
    combined with case. macOS filesystems treat them as one file."""
    return _unicode_from_tree(_tree(rel_paths)[1])


def _unicode_from_tree(by_dir: Dict[str, List[str]]) -> List[Finding]:
    # ASCII-only folders cannot differ by normalization (the case check already covers them)
    by_dir = {d: names for d, names in by_dir.items() if len(names) > 1 and not "".join(names).isascii()}
    # skip groups that are already plain case collisions on Windows
    return _collisions(by_dir, lambda n: windows_fold(mac_nfc(n)), "unicode_collision",
                       "paths differ only by Unicode normalization and are the same file on macOS",
                       skip_if=lambda g: len({windows_fold(p.rsplit('/', 1)[-1]) for p in g}) == 1,
                       show=_ascii_show)  # escaped, or NFC and NFD forms look identical


def _length_findings(rel_paths: Sequence[str], max_path: int, prefix_len: int,
                     dirs: Optional[Set[str]] = None) -> List[Finding]:
    # Folders get 12 fewer chars: CreateDirectoryW must leave room for an 8.3
    # file name (Git for Windows mingw_mkdir: "path limit is 248").
    if dirs is None:
        dirs = {_parent(r) for r in rel_paths} - {""}
    dir_max = max(max_path - DIR_RESERVE, 0)
    over: Dict[str, int] = {}
    floor = min(dir_max, max_path) - prefix_len
    for rel in rel_paths:
        if 2 * len(rel) < floor:
            continue  # UTF-16 length is at most 2x the code points: cannot be too long
        total = prefix_len + utf16_len(rel)
        if total >= (dir_max if rel in dirs else max_path):
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
        kind, limit = ("folder", dir_max - 1) if rel in dirs else ("path", max_path - 1)
        out.append(Finding(
            "warn", "path_length", rel,
            f"{kind} is about {total} chars once cloned under a {prefix_len}-char Windows folder "
            f"(limit {limit}){extra}; fails where long paths are not enabled "
            "(Git for Windows core.longpaths is off by default)"))
    return out


# --- 8.3 short names --------------------------------------------------------
#
# With 8.3 name generation on (Git's own comment: "at least on the C: drive by
# default"), NTFS gives every long name a hidden short alias: first 6 letters,
# '~', a counter ("Program Files" -> PROGRA~1). If a repo tracks both
# `longfilename.txt` and a file literally called `LONGFI~1.TXT`, only one of
# them can be created with that name, and the other silently wins or is renamed.
_SHORT_LOOKALIKE = re.compile(r"^([^~.\s]{1,6})~([0-9]+)(?:\.([^.\s]{0,3}))?$")
_SHORT_OK = re.compile(r"^[^.\s+,;=\[\]]{1,8}(?:\.[^.\s+,;=\[\]]{0,3})?$")


def _short_key(name: str) -> Optional[Tuple[str, str]]:
    """(first-6-letters, 3-letter extension) the Windows short name of a long ``name`` starts with."""
    if not name.isascii() or _SHORT_OK.match(name):
        return None  # non-ASCII needs the OEM code page (not modelled); 8.3-compliant names have no alias
    stem, dot, ext = name.rpartition(".")
    if not dot:
        stem, ext = name, ""
    stem = re.sub(r"[ .]", "", stem)
    stem = re.sub(r"[+,;=\[\]]", "_", stem)
    if not stem:
        return None
    return stem[:6].upper(), re.sub(r"[ .]", "", ext)[:3].upper()


def short_name_collisions(rel_paths: Iterable[str]) -> List[Finding]:
    """A file literally named like an 8.3 short name (``LONGFI~1.TXT``) next to
    a long name that Windows would give that very short name."""
    return _short_from_tree(_tree(rel_paths)[1])


def _short_from_tree(by_dir: Dict[str, List[str]]) -> List[Finding]:
    out: List[Finding] = []
    for parent, names in by_dir.items():
        if len(names) < 2:
            continue
        looks: Dict[Tuple[str, str], List[str]] = {}
        for name in names:
            if "~" not in name:
                continue
            m = _SHORT_LOOKALIKE.match(name)
            if m:
                looks.setdefault((m.group(1).upper(), (m.group(3) or "").upper()), []).append(name)
        if not looks:
            continue
        for name in names:
            key = _short_key(name)
            if key and key in looks:
                clash = sorted(looks[key])
                def full(n: str, parent: str = parent) -> str:
                    return parent + "/" + n if parent else n

                out.append(Finding(
                    "error", "short_name_collision", full(name),
                    f"{show_name(name)} gets the 8.3 short name {key[0]}~N"
                    f"{'.' + key[1] if key[1] else ''} on NTFS (when short names are enabled), "
                    f"the name of {', '.join(show_name(c) for c in clash)} in the same folder",
                    tuple([full(name)] + [full(c) for c in clash])))
    return out


# --- symlinks ---------------------------------------------------------------
_WIN_ABS = re.compile(r"^(?:[A-Za-z]:|\\\\)")


def symlink_findings(rel_paths: Sequence[str], symlinks: Dict[str, Optional[str]]) -> List[Finding]:
    """Checks that need to know which tracked paths are symlinks (and, when
    known, where they point). ``symlinks`` maps path -> target or None."""
    out: List[Finding] = []
    links = set(symlinks)
    for rel, target in symlinks.items():
        name = rel.rsplit("/", 1)[-1]
        out.append(Finding(
            "warn", "symlink", rel,
            "tracked symlink: on Windows it needs Developer Mode or admin rights plus core.symlinks=true; "
            "otherwise Git checks it out as a plain text file containing the link text"))
        kind = dotgit_kind(name)
        if kind and kind[0] != "git":
            out.append(Finding("error", "symlink_meta", rel,
                               f"a symlink named {show_name(name)} aliases .{kind[0]}: Git refuses to check these out "
                               "because a link there redirects what Git reads and writes"))
        if target is None:
            continue
        if _WIN_ABS.match(target) or target.startswith("/"):
            out.append(Finding("warn", "symlink_escape", rel,
                               f"absolute symlink target {show_name(target)} points outside the repository "
                               "and exists only on the machine that made it"))
        else:
            norm = posixpath.normpath(posixpath.join(_parent(rel), target.replace("\\", "/")))
            if norm == ".." or norm.startswith("../"):
                out.append(Finding("warn", "symlink_escape", rel,
                                   f"symlink target {show_name(target)} climbs out of the repository"))
        if "\\" in target:
            out.append(Finding("warn", "symlink_backslash", rel,
                               f"symlink target {show_name(target)} contains a backslash, which is a "
                               "path separator on Windows but an ordinary character elsewhere"))
    # a path *below* a tracked symlink: a checkout can be redirected through it
    for rel in rel_paths:
        parent = _parent(rel)
        while parent:
            if parent in links:
                out.append(Finding("error", "symlink_traversal", rel,
                                   f"lives below the tracked symlink {show_name(parent)}: a checkout can write "
                                   "through the link to wherever it points (CVE-2018-11235 style)", (rel, parent)))
                break
            parent = _parent(parent)
    return out


def scan_paths(
    rel_paths: Iterable[str],
    max_path: int = DEFAULT_MAX_PATH,
    prefix_len: int = DEFAULT_PREFIX_LEN,
    symlinks: Optional[Dict[str, Optional[str]]] = None,
    on_disk: bool = False,
) -> List[Finding]:
    """Check '/'-separated repo-relative paths. Pure: no filesystem access.

    Parent directories are derived automatically, so a plain file list (git
    index, ``git diff --name-only``) is enough. ``symlinks`` (path -> target or
    None) enables the symlink checks; ``on_disk`` tolerates a real ``.git`` folder.
    """
    paths, by_dir = _tree(rel_paths)
    findings: List[Finding] = []
    cache: Dict[str, List[Finding]] = {}
    for parent, names in by_dir.items():
        for name in names:
            res = cache.get(name)
            if res is None:
                res = cache[name] = check_component(name, where="", on_disk=on_disk)
            if res:
                rel = parent + "/" + name if parent else name
                findings.extend(Finding(f.severity, f.code, rel, f.detail) for f in res)
    findings.extend(_length_findings(paths, max_path, prefix_len, {d for d in by_dir if d}))
    findings.extend(_collisions(by_dir, windows_fold, "case_collision",
                                "paths differ only by case and cannot coexist on Windows", show=printable))
    findings.extend(_unicode_from_tree(by_dir))
    findings.extend(_short_from_tree(by_dir))
    if symlinks:
        findings.extend(symlink_findings(paths, symlinks))
    findings.sort(key=lambda f: (f.severity != "error", f.code, f.path))
    return findings


def walk_entries(root: str, skip: Sequence[str] = DEFAULT_SKIP,
                 follow_symlinks: bool = False) -> Tuple[List[str], Dict[str, Optional[str]]]:
    """Every file and directory under ``root`` as '/'-separated relative paths,
    plus a map of the symlinks among them (path -> target)."""
    out: List[str] = []
    links: Dict[str, Optional[str]] = {}
    seen: Set[Tuple[int, int]] = set()

    def rec(abs_dir: str, rel_dir: str) -> None:
        try:
            st = os.stat(abs_dir)
            key = (st.st_dev, st.st_ino)
            if key in seen:
                return  # symlink loop
            seen.add(key)
            entries = list(os.scandir(abs_dir))
        except OSError:
            return
        for e in entries:
            rel = rel_dir + e.name if not rel_dir else rel_dir + "/" + e.name
            islink = e.is_symlink()
            isdir = e.is_dir(follow_symlinks=follow_symlinks)
            if isdir and e.name in skip:
                continue
            out.append(rel)
            if islink:
                try:
                    links[rel] = os.readlink(e.path).replace(os.sep, "/") if os.sep != "/" else os.readlink(e.path)
                except OSError:
                    links[rel] = None
            if isdir:
                rec(e.path, rel)

    rec(root, "")
    return out, links


def walk_paths(root: str, skip: Sequence[str] = DEFAULT_SKIP, follow_symlinks: bool = False) -> List[str]:
    """Every file and directory under ``root`` as '/'-separated relative paths."""
    return walk_entries(root, skip, follow_symlinks)[0]


def _run_git(root: str, args: Sequence[str], timeout: float, stdin: Optional[bytes] = None) -> bytes:
    cmd = ["git", "-C", root] + list(args)
    try:
        proc = subprocess.run(cmd, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False)
    except FileNotFoundError as e:
        raise GitError("git is not installed or not on PATH") from e
    except subprocess.TimeoutExpired as e:
        raise GitError(f"git {args[0]} timed out after {timeout:g}s") from e
    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", "replace").strip() or f"exit {proc.returncode}"
        raise GitError(f"git {args[0]} failed: {msg}")
    return proc.stdout


def git_paths(root: str, timeout: float = 120.0) -> List[str]:
    """Tracked + staged paths from the git index under ``root`` (repo-relative).

    Reads the index, not the disk, so it sees exactly what a Windows clone gets
    — including paths your OS could never create. Raises :class:`GitError`.
    """
    return decode_nul_list(_run_git(root, ["ls-files", "-z", "--cached", "--full-name"], timeout))


def git_entries(root: str, timeout: float = 120.0) -> Tuple[List[str], Dict[str, Optional[str]]]:
    """Like :func:`git_paths`, plus the tracked symlinks (mode 120000) and their
    targets, read from the index and object store (nothing is checked out)."""
    raw = _run_git(root, ["ls-files", "-z", "--cached", "--stage", "--full-name"], timeout)
    paths: List[str] = []
    link_sha: Dict[str, str] = {}
    for rec in raw.split(b"\0"):
        if not rec:
            continue
        meta, _, path = rec.partition(b"\t")
        mode, sha = meta.split(b" ")[0], meta.split(b" ")[1]
        p = path.decode("utf-8", "surrogateescape")
        paths.append(p)
        if mode == b"120000":
            link_sha[p] = sha.decode("ascii")
    links: Dict[str, Optional[str]] = {}
    if link_sha:
        order = list(link_sha)
        try:
            data = _run_git(root, ["cat-file", "--batch"], timeout,
                            stdin=("\n".join(link_sha[p] for p in order) + "\n").encode("ascii"))
        except GitError:
            data = b""
        pos = 0
        for p in order:
            nl = data.find(b"\n", pos)
            if nl == -1:
                links[p] = None
                continue
            header = data[pos:nl].split(b" ")
            if len(header) != 3 or header[1] != b"blob":  # missing object, e.g. shallow/partial clone
                links[p] = None
                pos = nl + 1
                continue
            size = int(header[2])
            links[p] = data[nl + 1:nl + 1 + size].decode("utf-8", "surrogateescape")
            pos = nl + 1 + size + 1
    return paths, links


def git_added_paths(root: str, ref: str, timeout: float = 120.0) -> List[str]:
    """Index paths added (not merely modified) since ``ref``, renames counted as adds.
    Compares the index, which is what ``--git`` scans."""
    if ref.startswith("-"):
        raise GitError(f"refusing ref that looks like an option: {ref!r}")
    out = _run_git(root, ["diff", "--cached", "--name-only", "-z", "--no-renames", "--diff-filter=A", ref, "--"], timeout)
    return decode_nul_list(out)


def new_path_set(all_paths: Iterable[str], added_files: Iterable[str]) -> Set[str]:
    """Added files plus the directories that exist only because of them (a
    folder is *new* when every file under it is an added one)."""
    total: Counter = Counter()
    for p in all_paths:
        parent = _parent(p)
        while parent:
            total[parent] += 1
            parent = _parent(parent)
    added = set(added_files)
    got: Counter = Counter()
    for p in added:
        parent = _parent(p)
        while parent:
            got[parent] += 1
            parent = _parent(parent)
    new = set(added)
    new.update(d for d, n in got.items() if n == total[d])
    return new


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
    paths, links = walk_entries(root, skip, follow_symlinks)
    return scan_paths(paths, max_path=max_path, prefix_len=prefix_len, symlinks=links, on_disk=True)
