"""Baselines: adopt portacheck on a repo that already has findings.

``--write-baseline FILE`` records today's findings; ``--baseline FILE`` then
reports only findings that are not in it. A finding is identified by its code
and the exact bytes of its path (the first path for a collision), never by its
wording, so rewording a message in a later release does not resurface old debt.
"""
from __future__ import annotations

import hashlib
import json
from typing import Iterable, List, Sequence, Set, Tuple

from .rules import Finding

VERSION = 1


class BaselineError(ValueError):
    """The baseline file is missing or malformed (callers must fail closed)."""


def fingerprint(f: Finding) -> str:
    h = hashlib.sha256()
    h.update(f.code.encode("ascii", "replace"))
    h.update(b"\0")
    h.update(f.path.encode("utf-8", "surrogateescape"))
    return h.hexdigest()[:24]


def dumps(findings: Iterable[Finding]) -> str:
    fps = sorted({fingerprint(f) for f in findings})
    return json.dumps({"portacheck_baseline": VERSION, "fingerprints": fps}, indent=2) + "\n"


def loads(text: str) -> Set[str]:
    try:
        doc = json.loads(text)
        if doc.get("portacheck_baseline") != VERSION:
            raise BaselineError(f"unsupported baseline version {doc.get('portacheck_baseline')!r}")
        fps = doc["fingerprints"]
        if not isinstance(fps, list) or not all(isinstance(x, str) for x in fps):
            raise BaselineError("'fingerprints' must be a list of strings")
        return set(fps)
    except (ValueError, KeyError, AttributeError, TypeError) as e:
        if isinstance(e, BaselineError):
            raise
        raise BaselineError(f"not a portacheck baseline: {e}") from e


def apply(findings: Sequence[Finding], baseline: Set[str]) -> Tuple[List[Finding], int, int]:
    """(new findings, number suppressed, number of baseline entries that no longer match)."""
    new, hit = [], set()
    for f in findings:
        fp = fingerprint(f)
        if fp in baseline:
            hit.add(fp)
        else:
            new.append(f)
    return new, len(findings) - len(new), len(baseline - hit)
