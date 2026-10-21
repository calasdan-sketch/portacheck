"""Pure name rules — no filesystem needed, so they are trivially testable."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

# Windows reserves these as device names: unusable as file OR directory names,
# with or without an extension (CON.txt cannot be created either).
RESERVED = frozenset(
    ["CON", "PRN", "AUX", "NUL"]
    + [f"COM{i}" for i in range(1, 10)]
    + [f"LPT{i}" for i in range(1, 10)]
)

INVALID_CHARS = frozenset('<>:"|?*')


@dataclass(frozen=True)
class Finding:
    severity: str  # "error" | "warn"
    code: str
    path: str
    detail: str

    def as_dict(self):
        return {"severity": self.severity, "code": self.code, "path": self.path, "detail": self.detail}


def check_component(name: str, where: str = "") -> List[Finding]:
    """Check one path component (file or directory name)."""
    out: List[Finding] = []
    # Windows strips trailing dots/spaces from a component BEFORE name
    # resolution, so "AUX." and "AUX " are the reserved device name AUX.
    stem = name.rstrip(" .").split(".", 1)[0].upper()
    if stem in RESERVED:
        out.append(
            Finding("error", "reserved_name", where or name,
                    f"{name!r} collides with the Windows device name {stem}")
        )
    bad = sorted({c for c in name if c in INVALID_CHARS or ord(c) < 32})
    if bad:
        out.append(
            Finding("error", "invalid_char", where or name,
                    f"{name!r} contains character(s) Windows rejects: {' '.join(repr(c) for c in bad)}")
        )
    if name.endswith(" "):
        out.append(Finding("error", "trailing_space", where or name,
                           f"{name!r} ends with a space — Windows silently truncates it"))
    elif name.endswith("."):
        out.append(Finding("error", "trailing_dot", where or name,
                           f"{name!r} ends with a dot — Windows silently strips it"))
    if len(name) > 255:
        out.append(Finding("error", "component_too_long", where or name,
                           f"component is {len(name)} chars (filesystem limit is 255)"))
    return out


def check_relpath(rel: str) -> List[Finding]:
    """Check every component of a '/'-separated relative path."""
    out: List[Finding] = []
    for part in rel.split("/"):
        if part:
            out.extend(check_component(part, where=rel))
    return out
