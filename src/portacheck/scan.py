"""Walk a tree and collect portability findings, including case collisions."""
from __future__ import annotations

import os
from typing import Dict, Iterable, List, Sequence

from .rules import Finding, check_component

DEFAULT_SKIP = (".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache")


def case_collisions(rel_paths: Iterable[str]) -> List[Finding]:
    """Group paths by casefold; groups with more than one original are collisions.

    Pure — fed any iterable of relative paths, so the logic is testable even on
    case-insensitive filesystems that cannot physically hold both names.
    """
    index: Dict[str, List[str]] = {}
    for rel in rel_paths:
        index.setdefault(rel.casefold(), []).append(rel)
    out: List[Finding] = []
    for files in index.values():
        originals = sorted(set(files))
        if len(originals) > 1:
            out.append(
                Finding("error", "case_collision", originals[0],
                        "paths differ only by case and cannot coexist on Windows: "
                        + ", ".join(originals))
            )
    out.sort(key=lambda f: f.path)
    return out


def scan_tree(
    root: str,
    max_path: int = 260,
    skip: Sequence[str] = DEFAULT_SKIP,
    follow_symlinks: bool = False,
) -> List[Finding]:
    """Scan ``root`` for Windows portability hazards.

    * per-component name rules (reserved names, invalid characters, trailing
      dot/space, over-long components)
    * case-insensitive collisions anywhere in the tree (``Foo.md`` vs ``foo.md``
      cannot coexist in a git checkout on Windows)
    * absolute path length vs ``max_path`` (warn — the long-path feature can
      mitigate it, but plenty of tooling still breaks)
    """
    findings: List[Finding] = []
    seen: List[str] = []

    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in list(dirnames) + list(filenames):
            rel = os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/")
            findings.extend(check_component(name, where=rel))
            seen.append(rel)

        abs_dir = os.path.abspath(dirpath)
        if len(abs_dir) > max_path:
            findings.append(
                Finding("warn", "path_length",
                        os.path.relpath(dirpath, root).replace(os.sep, "/") or ".",
                        f"directory path is {len(abs_dir)} chars (> {max_path}); "
                        "breaks tools that don't opt into long-path support")
            )

    findings.extend(case_collisions(seen))
    findings.sort(key=lambda f: (f.severity != "error", f.code, f.path))
    return findings
