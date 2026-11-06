"""Pure name rules — no filesystem needed, so they are trivially testable."""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from typing import List

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

    def as_dict(self):
        return {"severity": self.severity, "code": self.code, "path": self.path, "detail": self.detail}


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
    out, seg = [], []
    for c in s:
        if _is_cjk_compat(c):
            out.append(unicodedata.normalize("NFC", "".join(seg)))
            out.append(c)
            seg = []
        else:
            seg.append(c)
    out.append(unicodedata.normalize("NFC", "".join(seg)))
    return "".join(out)


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


def check_component(name: str, where: str = "") -> List[Finding]:
    """Check one path component (file or directory name)."""
    out: List[Finding] = []
    if name in (".", ".."):
        return out  # relative-path markers, not names (Git allows them too)
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
    if ascii_only:
        return out
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


def check_relpath(rel: str) -> List[Finding]:
    """Check every component of a '/'-separated relative path."""
    out: List[Finding] = []
    for part in rel.split("/"):
        if part:
            out.extend(check_component(part, where=rel))
    return out
