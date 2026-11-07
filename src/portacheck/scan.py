"""Collect portability findings from a directory walk, the git index, or a path list."""
from __future__ import annotations

import posixpath
import re
import os
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .rules import (Finding, check_component, dotgit_kind, mac_nfc, path_bytes, printable, show_name,
                    skeleton, utf16_len, windows_fold)

DEFAULT_SKIP = (".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache")

#: Assumed length of the Windows directory a repo is cloned into, *including*
#: the trailing backslash, e.g. ``C:\Users\jane.doe\source\repos\project\``
#: (39 chars). Override with ``prefix_len`` / ``--prefix-len``.
DEFAULT_PREFIX_LEN = 50

#: Windows MAX_PATH. It counts the terminating NUL, so 259 visible chars is
#: the longest path that works without long-path support.
DEFAULT_MAX_PATH = 260

#: macOS's PATH_MAX (sys/syslimits.h) and Linux's (linux/limits.h), in bytes including the NUL. Only the
#: repo-relative part is measured, so a real checkout is longer still.
MACOS_PATH_MAX = 1024
LINUX_PATH_MAX = 4096

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
                show: Callable[[str], str] = str, severity: str = "error") -> List[Finding]:
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
            out.append(Finding(severity, code, originals[0], why + ": " + ", ".join(map(show, originals)),
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


def _confusable_from_tree(by_dir: Dict[str, List[str]]) -> List[Finding]:
    by_dir = {d: names for d, names in by_dir.items() if len(names) > 1 and not "".join(names).isascii()}
    return _collisions(by_dir, skeleton, "confusable_name",
                       "names are different files but look alike (look-alike letters or compatibility forms)",
                       skip_if=lambda g: len({windows_fold(mac_nfc(p.rsplit('/', 1)[-1])) for p in g}) == 1,
                       show=_ascii_show, severity="warn")


def _shallowest(over: Dict[str, int]) -> Tuple[List[str], Dict[str, int]]:
    """(the over-limit paths whose parent is not itself over the limit, count of
    over-limit paths inside each). Linear: every path remembers its top."""
    top: Dict[str, str] = {}
    for rel in over:
        chain: List[str] = []
        cur = rel
        while cur not in top:
            chain.append(cur)
            p = _parent(cur)
            if p in over:
                cur = p
            else:
                break
        base = top[cur] if cur in top else chain[-1]
        for c in chain:
            top[c] = base
    inside_count: Dict[str, int] = {}
    for rel, t in top.items():
        if t != rel:
            inside_count[t] = inside_count.get(t, 0) + 1
    return [rel for rel in over if top[rel] == rel], inside_count


def _posix_length_findings(paths: Sequence[str], dirs: Set[str]) -> List[Finding]:
    over: Dict[str, int] = {}
    for rel in paths:
        if len(rel) >= 256:  # fewer than 256 characters cannot reach 1024 bytes: skip the encode
            n = len(path_bytes(rel)) + 1
            if n >= MACOS_PATH_MAX:
                over[rel] = n
    tops, inside_count = _shallowest(over)
    out = []
    for rel in tops:
        inside = inside_count.get(rel, 0)
        extra = f" (+{inside} path(s) inside it)" if inside else ""
        kind = "folder" if rel in dirs else "path"
        out.append(Finding("warn", "path_length_posix", rel,
                           f"{kind} is {over[rel] - 1} UTF-8 bytes on its own; macOS's PATH_MAX is "
                           f"{MACOS_PATH_MAX} and Linux's {LINUX_PATH_MAX} (both count the NUL), and the clone "
                           f"folder comes on top{extra}"))
    return out


#: how many offending components of one huge path are listed (naming each needs a prefix copy of the path)
_HUGE_COMPONENT_REPORTS = 20


def _huge_findings(huge: Sequence[str], on_disk: bool) -> List[Finding]:
    """Paths of ``LINUX_PATH_MAX`` bytes or more. They cannot be created on Linux or macOS, and
    folding every prefix of one into the folder tree would cost memory quadratic in its length, so they are
    checked component by component and kept out of the collision tree."""
    out: List[Finding] = []
    for rel in huge:
        out.append(Finding("error", "path_length_posix", rel,
                           f"path is {len(path_bytes(rel))} UTF-8 bytes; Linux's PATH_MAX is {LINUX_PATH_MAX} and "
                           f"macOS's {MACOS_PATH_MAX} (both count the NUL), so it cannot be checked out there "
                           "(not included in the collision checks)"))
        verdicts: Dict[str, List[Finding]] = {}
        end = 0
        reported = 0
        for name in rel.split("/"):
            end += len(name)
            res = verdicts.get(name)
            if res is None:
                res = verdicts[name] = check_component(name, where="", on_disk=on_disk)
            if res and reported < _HUGE_COMPONENT_REPORTS:
                reported += 1
                where = rel[:end]  # the offending component's own path, so a fix script renames the right thing
                out.extend(Finding(f.severity, f.code, where, f.detail) for f in res)
            end += 1
    return out


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
    tops, inside_count = _shallowest(over)
    out: List[Finding] = []
    for rel in tops:
        total = over[rel]
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
    huge: List[str] = []

    def bounded() -> Iterable[str]:
        for rel in rel_paths:
            if len(rel) >= MACOS_PATH_MAX and len(path_bytes(rel)) >= LINUX_PATH_MAX:
                huge.append(rel)
            else:
                yield rel

    paths, by_dir = _tree(bounded())
    findings: List[Finding] = _huge_findings(huge, on_disk)
    cache: Dict[str, List[Finding]] = {}
    for parent, names in by_dir.items():
        for name in names:
            res = cache.get(name)
            if res is None:
                res = cache[name] = check_component(name, where="", on_disk=on_disk)
            if res:
                rel = parent + "/" + name if parent else name
                findings.extend(Finding(f.severity, f.code, rel, f.detail) for f in res)
    dirs = {d for d in by_dir if d}
    findings.extend(_length_findings(paths, max_path, prefix_len, dirs))
    findings.extend(_posix_length_findings(paths, dirs))
    findings.extend(_collisions(by_dir, windows_fold, "case_collision",
                                "paths differ only by case and cannot coexist on Windows", show=printable))
    findings.extend(_unicode_from_tree(by_dir))
    findings.extend(_short_from_tree(by_dir))
    findings.extend(_confusable_from_tree(by_dir))
    if symlinks:
        findings.extend(symlink_findings(paths, symlinks))
    findings.sort(key=lambda f: (f.severity != "error", f.code, f.path))
    return findings


def walk_entries(root: str, skip: Sequence[str] = DEFAULT_SKIP,
                 follow_symlinks: bool = False,
                 errors: Optional[List[str]] = None) -> Tuple[List[str], Dict[str, Optional[str]]]:
    """Every file and directory under ``root`` as '/'-separated relative paths,
    plus a map of the symlinks among them (path -> target).

    Iterative, so a hostile 100,000-level folder tree cannot exhaust the Python
    stack. Folders that cannot be read are appended to ``errors`` (when given)
    instead of being silently skipped.
    """
    out: List[str] = []
    links: Dict[str, Optional[str]] = {}
    seen: Set[Tuple[int, int]] = set()

    def open_dir(abs_dir: str, rel_dir: str):
        try:
            st = os.stat(abs_dir)
            key = (st.st_dev, st.st_ino)
            if key in seen:
                return None  # symlink loop
            seen.add(key)
            return iter(list(os.scandir(abs_dir)))
        except OSError:
            if errors is not None:
                errors.append(rel_dir or ".")
            return None

    first = open_dir(root, "")
    stack = [("", root, first)] if first is not None else []
    while stack:
        rel_dir, abs_dir, it = stack[-1]
        for e in it:
            rel = rel_dir + "/" + e.name if rel_dir else e.name
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
                sub = open_dir(e.path, rel)
                if sub is not None:
                    stack.append((rel, e.path, sub))
                    break  # descend now: same pre-order as a recursive walk
        else:
            stack.pop()
    return out, links


def walk_paths(root: str, skip: Sequence[str] = DEFAULT_SKIP, follow_symlinks: bool = False) -> List[str]:
    """Every file and directory under ``root`` as '/'-separated relative paths."""
    return walk_entries(root, skip, follow_symlinks)[0]


def _git_env() -> Dict[str, str]:
    env = dict(os.environ)
    env.update({"GIT_OPTIONAL_LOCKS": "0",      # a read-only scan must not take the index lock
                "GIT_NO_LAZY_FETCH": "1",       # in a partial clone, never contact the remote (Git 2.44+)
                "GIT_TERMINAL_PROMPT": "0"})
    return env


#: git settings forced on every call: a hostile repository's own config cannot run its fsmonitor hook
#: through us, and a repo-level diff.relative cannot hide paths outside the folder we were pointed at.
_GIT_FLAGS = ["-c", "core.fsmonitor=false", "-c", "diff.relative=false"]


def _run_git(root: str, args: Sequence[str], timeout: float, stdin: Optional[bytes] = None) -> bytes:
    cmd = ["git", "-C", root] + _GIT_FLAGS + list(args)
    try:
        proc = subprocess.run(cmd, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False, env=_git_env())
    except FileNotFoundError as e:
        raise GitError("git is not installed or not on PATH") from e
    except subprocess.TimeoutExpired as e:
        raise GitError(f"git {args[0]} timed out after {timeout:g}s") from e
    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", "replace").strip() or f"exit {proc.returncode}"
        raise GitError(f"git {args[0]} failed: {msg}")
    return proc.stdout


def git_paths(root: str, timeout: float = 120.0) -> List[str]:
    """Tracked + staged paths of the whole repository that contains ``root`` (repo-relative).

    Reads the index, not the disk, so it sees exactly what a Windows clone gets
    — including paths your OS could never create. Raises :class:`GitError`.
    """
    return decode_nul_list(_run_git(root, ["ls-files", "-z", "--cached", "--full-name", "--", ":/"], timeout))


@dataclass
class Snapshot:
    """What a clone of one tree would contain: paths, symlink targets, and the root ``.gitmodules`` bytes."""
    paths: List[str] = field(default_factory=list)
    symlinks: Dict[str, Optional[str]] = field(default_factory=dict)
    #: bytes of the root .gitmodules (at most GITMODULES_MAX + 1), None when there is none
    gitmodules: Optional[bytes] = None


def _read_blobs(root: str, shas: Sequence[str], timeout: float) -> Dict[str, Optional[bytes]]:
    """Contents of blobs (sha -> bytes, None when the object is missing, e.g. a shallow/partial clone)."""
    got: Dict[str, Optional[bytes]] = {}
    uniq = list(dict.fromkeys(shas))
    if not uniq:
        return got
    try:
        data = _run_git(root, ["cat-file", "--batch"], timeout, stdin=("\n".join(uniq) + "\n").encode("ascii"))
    except GitError:
        return {sha: None for sha in uniq}
    pos = 0
    for sha in uniq:
        nl = data.find(b"\n", pos)
        if nl == -1:
            got[sha] = None
            continue
        header = data[pos:nl].split(b" ")
        if len(header) != 3 or header[1] != b"blob":
            got[sha] = None
            pos = nl + 1
            continue
        size = int(header[2])
        got[sha] = data[nl + 1:nl + 1 + size]
        pos = nl + 1 + size + 1
    return got


def _gitmodules_prefix(root: str, sha: str, limit: int, timeout: float) -> Optional[bytes]:
    """The first ``limit`` + 1 bytes of a blob, without loading a huge one into memory."""
    try:
        proc = subprocess.Popen(["git", "-C", root] + _GIT_FLAGS + ["cat-file", "blob", sha],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=_git_env())
    except OSError:
        return None
    try:
        assert proc.stdout is not None
        data = proc.stdout.read(limit + 1)
    finally:
        proc.kill()
        proc.stdout.close()
        proc.wait()
    return data


def _snapshot_from(root: str, records: Sequence[Tuple[str, str, str]], timeout: float) -> Snapshot:
    """records: (mode, sha, path) triples straight from git."""
    from .content import GITMODULES_MAX

    snap = Snapshot()
    link_sha: Dict[str, str] = {}
    gm_sha: Optional[str] = None
    for mode, sha, p in records:
        snap.paths.append(p)
        if mode == "120000":
            link_sha[p] = sha
        elif p == ".gitmodules" and mode in ("100644", "100755"):
            gm_sha = sha
    blobs = _read_blobs(root, list(link_sha.values()), timeout)
    for p, sha in link_sha.items():
        raw = blobs.get(sha)
        snap.symlinks[p] = None if raw is None else raw.decode("utf-8", "surrogateescape")
    if gm_sha:
        snap.gitmodules = _gitmodules_prefix(root, gm_sha, GITMODULES_MAX, timeout)
    return snap


def git_snapshot(root: str, rev: Optional[str] = None, timeout: float = 120.0) -> Snapshot:
    """The tracked tree of the whole repository containing ``root``: the index, or the tree of commit-ish ``rev``
    (a branch, tag or hash; nothing is checked out). Raises :class:`GitError`."""
    records: List[Tuple[str, str, str]] = []
    if rev is None:
        raw = _run_git(root, ["ls-files", "-z", "--cached", "--stage", "--full-name", "--", ":/"], timeout)
        for rec in raw.split(b"\0"):
            if not rec:
                continue
            meta, _, path = rec.partition(b"\t")
            parts = meta.split(b" ")
            records.append((parts[0].decode("ascii"), parts[1].decode("ascii"), path.decode("utf-8", "surrogateescape")))
    else:
        if rev.startswith("-"):
            raise GitError(f"refusing revision that looks like an option: {rev!r}")
        _run_git(root, ["rev-parse", "--verify", "--quiet", rev + "^{tree}"], timeout)
        raw = _run_git(root, ["ls-tree", "-r", "-z", "--full-tree", rev, "--"], timeout)
        for rec in raw.split(b"\0"):
            if not rec:
                continue
            meta, _, path = rec.partition(b"\t")
            parts = meta.split(b" ")  # mode type sha
            records.append((parts[0].decode("ascii"), parts[2].decode("ascii"), path.decode("utf-8", "surrogateescape")))
    return _snapshot_from(root, records, timeout)


def git_entries(root: str, timeout: float = 120.0) -> Tuple[List[str], Dict[str, Optional[str]]]:
    """Like :func:`git_paths`, plus the tracked symlinks (mode 120000) and their
    targets, read from the index and object store (nothing is checked out)."""
    snap = git_snapshot(root, None, timeout)
    return snap.paths, snap.symlinks


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
        if len(p) >= LINUX_PATH_MAX:
            continue  # kept out of the folder tree (see scan_paths)
        parent = _parent(p)
        while parent:
            total[parent] += 1
            parent = _parent(parent)
    added = set(added_files)
    got: Counter = Counter()
    for p in added:
        if len(p) >= LINUX_PATH_MAX:
            continue
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
