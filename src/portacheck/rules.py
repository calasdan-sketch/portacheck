"""Pure name rules — no filesystem needed, so they are trivially testable."""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from functools import lru_cache
import re
from typing import List, Optional, Tuple

# Windows reserves these as device names: unusable as file OR directory names,
# with or without an extension (CON.txt cannot be created either). Microsoft's
# "Naming Files, Paths, and Namespaces" page also lists the ISO-8859-1
# superscript digits ¹ ² ³ as valid COM#/LPT# digits, so COM¹ is reserved too.
#
# Git for Windows refuses a few more at checkout (compat/mingw.c,
# is_valid_win32_path, with core.protectNTFS on — the default): CONIN$ and
# CONOUT$, and LPT0 (it accepts any digit after LPT, but only 1-9 after COM).
# portacheck reserves the union of both lists.
_SUPERSCRIPTS = ["\u00b9", "\u00b2", "\u00b3"]
RESERVED = frozenset(
    ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
    + [f"COM{d}" for d in [str(i) for i in range(1, 10)] + _SUPERSCRIPTS]
    + [f"LPT{d}" for d in [str(i) for i in range(0, 10)] + _SUPERSCRIPTS]
)

# '\\' is legal in a POSIX filename but is a path separator on Windows.
INVALID_CHARS = frozenset('<>:"|?*\\')

#: NTFS limits a component to 255 UTF-16 code units.
COMPONENT_MAX = 255


@dataclass(frozen=True)
class Finding:
    severity: str  # "error" | "warn"
    code: str
    path: str
    detail: str
    #: every path involved (collision members); empty for single-path findings
    paths: Tuple[str, ...] = ()
    #: extra identity for findings that share a code and path (e.g. several
    #: hazards inside one .gitmodules); part of the baseline fingerprint
    ident: str = ""

    def as_dict(self):
        d = {"severity": self.severity, "code": self.code, "path": self.path, "detail": self.detail}
        if self.paths:
            d["paths"] = list(self.paths)
        return d


def path_bytes(s: str) -> bytes:
    """The exact bytes of a decoded path (undecodable bytes restored). Never raises:
    a lone surrogate that is not a raw byte (only possible from the Python API) is escaped."""
    try:
        return s.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        return s.encode("utf-8", "backslashreplace")


def utf16_len(s: str) -> int:
    """Length as Windows counts it (UTF-16 code units; astral chars count 2)."""
    if s.isascii():
        return len(s)
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def windows_fold(s: str) -> str:
    """Approximate the NTFS case-insensitive comparison.

    NTFS compares names through a per-code-unit uppercase table, i.e. *simple*
    one-to-one uppercase mappings only. Full case folding (``str.casefold``)
    would wrongly equate ``straße`` and ``strasse``; NTFS does not. Characters
    outside the BMP are left alone. This is an approximation: the real table
    is stored per volume and varies by Windows version.
    """
    if s.isascii():
        return s.upper()
    return "".join(map(_fold_char, s))


@lru_cache(maxsize=4096)
def _fold_char(c: str) -> str:
    if ord(c) > 0xFFFF:
        return c
    u = c.upper()
    return u if len(u) == 1 else c


def _is_cjk_compat(c: str) -> bool:
    o = ord(c)
    return 0xF900 <= o <= 0xFAFF or 0x2F800 <= o <= 0x2FA1F


def mac_nfc(s: str) -> str:
    """NFC, except CJK compatibility ideographs are kept as they are.

    NFC maps e.g. U+F900 to U+8C48, but HFS+ excludes these ideographs from
    its decomposition (APFS behaviour is unverified), so flagging them would be
    a false positive.
    """
    if s.isascii():
        return s
    if not any(_is_cjk_compat(c) for c in s):
        return unicodedata.normalize("NFC", s)
    out: List[str] = []
    seg: List[str] = []
    for c in s:
        if _is_cjk_compat(c):
            out.append(unicodedata.normalize("NFC", "".join(seg)))
            out.append(c)
            seg = []
        else:
            seg.append(c)
    out.append(unicodedata.normalize("NFC", "".join(seg)))
    return "".join(out)


# --- look-alike names -----------------------------------------------------------
#
# A deliberately small, high-confidence subset of Unicode's confusables.txt
# (UTS #39): Cyrillic and Greek letters that render like a Latin letter in
# common fonts. It is not the full table, so a pair outside it is not flagged.
_CONFUSABLE = {}
for _src, _dst in (
        # Cyrillic lower case, then upper case
        ("\u0430\u0441\u0435\u043e\u0440\u0445\u0443\u0456\u0458\u0455\u04bb\u0501\u051b\u051d",
         "acceopxyijshdqw"),
        ("\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0425\u0406\u0408\u0405",
         "ABEKMHOPCTXIJS"),
        # Greek
        ("\u0391\u0392\u0395\u0396\u0397\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a5\u03a7"
         "\u03bf\u03bd",
         "ABEZHIKMNOPTYXov")):
    for _a, _b in zip(_src, _dst):
        _CONFUSABLE[_a] = _b
_NON_LATIN_LOOKALIKE = frozenset(_CONFUSABLE)


def skeleton(name: str) -> str:
    """Name with compatibility forms (ligatures, full-width) and the look-alike
    letters above mapped to Latin, then case-folded the Windows way."""
    if name.isascii():
        return windows_fold(name)
    n = unicodedata.normalize("NFKC", name)
    return windows_fold("".join(_CONFUSABLE.get(c, c) for c in n))


def mixes_scripts(name: str) -> bool:
    """A single word that mixes Latin letters with a Cyrillic/Greek look-alike
    (``p\u0430ypal``). Words from one script, and Latin next to Greek/Cyrillic
    in *separate* words, are fine."""
    if name.isascii() or not (_NON_LATIN_LOOKALIKE & set(name)):
        return False
    for word in re.findall(r"[^\W\d_]+", name):
        has_lookalike = any(c in _NON_LATIN_LOOKALIKE for c in word)
        has_latin = any(c.isascii() and c.isalpha() for c in word)
        if has_lookalike and has_latin:
            return True
    return False


#: files that are tool or OS metadata, not source (matched case-insensitively)
OS_JUNK = frozenset([".ds_store", "thumbs.db", "desktop.ini", ".appledouble", ".spotlight-v100", ".trashes"])


def is_os_junk(name: str) -> bool:
    low = name.lower()
    return low in OS_JUNK or (low.startswith("._") and len(low) > 2)


def printable(s: str, escape_backslash: bool = True) -> str:
    """Make an untrusted string safe to print on a terminal, CI log or report.

    Control, bidi/zero-width format and line/paragraph separator characters
    become ``\\uXXXX``; undecodable raw bytes (surrogate escapes) become
    ``\\xNN``. Backslashes are doubled by default so a real ``\\u202e`` typed
    into a name cannot pass for an escape portacheck produced.
    """
    out = []
    for c in s:
        o = ord(c)
        if 0xDC80 <= o <= 0xDCFF:  # surrogateescape'd raw byte
            out.append(f"\\x{o - 0xDC00:02x}")
        elif o == 0x5C and escape_backslash:
            out.append("\\\\")
        elif o < 32 or o == 127 or 0x80 <= o < 0xA0 or unicodedata.category(c) in ("Cf", "Cs", "Zl", "Zp"):
            out.append(f"\\u{o:04x}")
        else:
            out.append(c)
    return "".join(out)


def show_name(name: str, limit: int = 200) -> str:
    """Quoted, escaped form of a name for finding details (raw bytes as \\xNN)."""
    if len(name) > limit:
        name = name[:80] + "..."
    return "'" + printable(name).replace("'", "\\'") + "'"


def _invisible(c: str) -> bool:
    # Cf = format chars: bidi overrides (U+202E ...), zero-width space/joiners,
    # BOM, soft hyphen. Legal in names but render invisibly or reorder text.
    return unicodedata.category(c) == "Cf"


# --- names Git itself protects (path.c: is_ntfs_dotgit*, is_hfs_dotgit*) ----
#
# On NTFS, ".git" is also reachable as ".git . .", "git~1" (8.3 short name) and
# ".git::$INDEX_ALLOCATION"; on HFS+, as ".g<ZWNJ>it". A tracked path through
# any of these writes into the repository's own metadata (hooks!) during a
# checkout: the CVE-2014-9390 / CVE-2019-1350 family. These are ports of Git's
# own predicates; the tests cross-check them against `git update-index
# --cacheinfo` with core.protectNTFS/core.protectHFS on a real git.

#: HFS+ ignores these code points completely when comparing names (utf8.c).
HFS_IGNORABLE = frozenset(
    [0x200c, 0x200d, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
     0x206a, 0x206b, 0x206c, 0x206d, 0x206e, 0x206f, 0xfeff])

#: dot-file -> NTFS hash-based fall-back short-name prefix used by Git.
_DOT_META = {
    "gitmodules": "gi7eba",
    "gitattributes": "gi7d29",
    "gitignore": "gi250a",
    "mailmap": "maba30",
}
#: forged aliases of these change what Git executes/reads (error); others warn
META_SEVERE = frozenset({"git", "gitmodules", "gitattributes"})


def _tail_ok(rest: str) -> bool:
    """Only spaces/dots, optionally followed by an NTFS ':stream' suffix."""
    for c in rest:
        if c == ":":
            return True
        if c not in " .":
            return False
    return True


def ntfs_dotgit(name: str) -> bool:
    """Git's is_ntfs_dotgit: '.git' or 'git~1' + trailing dots/spaces/':stream'."""
    low = name.lower()
    if low.startswith(".git"):
        return _tail_ok(name[4:])
    if low.startswith("git~1"):
        return _tail_ok(name[5:])
    return False


def ntfs_dot_meta(name: str) -> Optional[str]:
    """Key of the gitmodules/gitattributes/gitignore/mailmap file ``name``
    aliases on NTFS (any case, trailing dots/spaces/streams, ``~1``-``~4``
    short names, hash fall-back short names) or None. Includes the canonical spelling."""
    low = name.lower()
    for key, fb in _DOT_META.items():
        if low.startswith("." + key) and _tail_ok(name[len(key) + 1:]):
            return key
        if low[:6] == key[:6] and low[6:7] == "~" and low[7:8] in ("1", "2", "3", "4") and _tail_ok(name[8:]):
            return key
        m = re.match(re.escape(fb) + r"~[0-9]+", low)
        if m and _tail_ok(name[m.end():]):
            return key
    return None


def hfs_fold(name: str) -> str:
    """Name as HFS+ compares it for Git's checks: ignorable code points removed, lowercased."""
    if name.isascii():
        return name.lower()
    return "".join(c for c in name if ord(c) not in HFS_IGNORABLE).lower()


def dotgit_kind(name: str) -> Optional[Tuple[str, bool]]:
    """Classify a path component as Git metadata or an alias of it.

    Returns ``(kind, canonical)``; kind is ``git``, ``gitmodules``,
    ``gitattributes``, ``gitignore`` or ``mailmap``; ``canonical`` is True only
    for the exact lowercase spelling (``.gitmodules``). None if unrelated.
    A backslash is a separator here, as in ``git fsck``.
    """
    for piece in name.split("\\"):
        if not piece:
            continue
        if ntfs_dotgit(piece):
            return "git", False
        folded = hfs_fold(piece)
        if folded == ".git":
            return "git", False
        for key in _DOT_META:
            if folded == "." + key:
                return key, piece == "." + key
        k = ntfs_dot_meta(piece)
        if k:
            return k, False
    return None


# printable ASCII with none of the characters Windows rejects, no leading/trailing space or dot
_EDGE = r"[A-Za-z0-9_+=,;@#%&()\[\]{}!$^'`~-]"  # may start or end a name
_SAFE_ASCII = re.compile(_EDGE + r"(?:[A-Za-z0-9_+=,;@#%&()\[\]{}!$^'` ~.-]*" + _EDGE + ")?")
#: first letters of names that may need the Git-metadata check (".git*", "git~1", "gitmod~1", "gi7eba~1", "mailma~1")
_META_START = frozenset(".gGmM")


def check_component(name: str, where: str = "", on_disk: bool = False) -> List[Finding]:
    """Check one path component (file or directory name).

    ``on_disk``: the name comes from a working-tree walk, where a real ``.git``
    folder is normal; only *aliases* of it (``git~1``, ``.git.``) are reported.
    """
    out: List[Finding] = []
    if name in (".", "..", ""):
        return out  # relative-path markers / empty: scan_paths(strict_dots=True) reports them for git sources
    # Fast path: the overwhelmingly common clean ASCII name (no regex of rules, one fullmatch).
    if name[0] not in _META_START and len(name) <= COMPONENT_MAX and _SAFE_ASCII.fullmatch(name):
        i = name.find(".")
        if name[:i if i != -1 else None].rstrip(" ").upper() not in RESERVED:
            if name[0] in "Tt" and name.lower() == "thumbs.db" or name[0] in "Dd" and name.lower() == "desktop.ini":
                out.append(_junk_finding(name, where))
            return out
    loc = where or name
    shown = show_name(name)
    # Windows strips trailing dots/spaces, and a device name stays reserved
    # when spaces, an extension or an NTFS stream follow it: "AUX.", "CON .txt",
    # "nul:x" are all the device. Cut at the first '.' or ':', drop spaces.
    cut = len(name)
    for sep in ".:":
        i = name.find(sep)
        if i != -1:
            cut = min(cut, i)
    stem = name[:cut].rstrip(" ").upper()
    if stem in RESERVED:
        out.append(
            Finding("error", "reserved_name", loc,
                    f"{shown} collides with the Windows device name {stem}")
        )
    kind = dotgit_kind(name)
    if kind is not None:
        k, canonical = kind
        if k == "git" and on_disk and name == ".git":
            pass
        elif k == "git":
            out.append(Finding("error", "git_dir_alias", loc,
                               f"{shown} is, or aliases, the .git directory (NTFS trailing dots/spaces, "
                               "git~1 short name, :stream, HFS+ ignorable characters): a checkout through it "
                               "can overwrite .git/hooks (Git refuses such paths)"))
        elif not canonical:
            out.append(Finding("error" if k in META_SEVERE else "warn", "git_meta_alias", loc,
                               f"{shown} is a non-canonical spelling/alias of .{k}: "
                               "on a case- or alias-insensitive filesystem Git reads it as the real file"))
    bad = sorted({c for c in name if c in INVALID_CHARS or ord(c) < 32})
    if bad:
        out.append(
            Finding("error", "invalid_char", loc,
                    f"{shown} contains character(s) Windows rejects: {' '.join(show_name(c) for c in bad)}")
        )
    ascii_only = name.isascii()
    if not ascii_only and any(0xD800 <= ord(c) <= 0xDFFF for c in name):
        out.append(Finding("error", "invalid_encoding", loc,
                           f"{shown} is not valid UTF-8 — Git for Windows cannot check it out faithfully"))
    if name.endswith(" "):
        out.append(Finding("error", "trailing_space", loc,
                           f"{shown} ends with a space — Windows silently truncates it"))
    elif name.endswith("."):
        out.append(Finding("error", "trailing_dot", loc,
                           f"{shown} ends with a dot — Windows silently strips it"))
    n16 = utf16_len(name)
    if n16 > COMPONENT_MAX:
        out.append(Finding("error", "component_too_long", loc,
                           f"component is {n16} UTF-16 units (NTFS limit is {COMPONENT_MAX})"))
    if is_os_junk(name):
        out.append(_junk_finding(name, where))
    if ascii_only:
        return out
    nbytes = len(path_bytes(name)) if n16 <= COMPONENT_MAX else 0
    if nbytes > COMPONENT_MAX:
        out.append(Finding("warn", "component_bytes", loc,
                           f"name is {nbytes} UTF-8 bytes; Linux file systems (ext4, btrfs, XFS: NAME_MAX) allow "
                           f"{COMPONENT_MAX}, so it cannot be created there although NTFS counts only {n16} UTF-16 units"))
    if mixes_scripts(name):
        out.append(Finding("warn", "mixed_script", loc,
                           f"{shown} mixes Latin letters with Cyrillic/Greek look-alikes inside one word — "
                           "it can pass for a different name"))
    hidden = sorted({c for c in name if _invisible(c)})
    if hidden:
        out.append(Finding("warn", "invisible_char", loc,
                           f"{shown} contains invisible/bidi format character(s) "
                           + " ".join(f"U+{ord(c):04X}" for c in hidden)
                           + " — the name can display differently from what it is"))
    nfc = mac_nfc(name)
    if nfc != name:
        out.append(Finding("warn", "not_nfc", loc,
                           f"{ascii(name[:80])} is not NFC-normalized (composed form: {ascii(nfc[:80])}); "
                           "macOS and Linux tools can treat the two as different files"))
    return out


def _junk_finding(name: str, where: str) -> Finding:
    return Finding("warn", "os_junk", where or name,
                   f"{show_name(name)} is operating-system metadata (Finder, Explorer or AppleDouble), not source: "
                   "usually committed by accident; ignore it in .gitignore")


def check_relpath(rel: str, on_disk: bool = False) -> List[Finding]:
    """Check every component of a '/'-separated relative path."""
    out: List[Finding] = []
    for part in rel.split("/"):
        if part:
            out.extend(check_component(part, where=rel, on_disk=on_disk))
    return out
