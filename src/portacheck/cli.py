"""portacheck CLI: scan a path and report portability hazards."""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .scan import DEFAULT_SKIP, scan_tree


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="portacheck",
        description="Find repo paths that break Windows checkouts before Windows does.",
    )
    ap.add_argument("path", nargs="?", default=".", help="directory to scan (default: .)")
    ap.add_argument("--max-path", type=int, default=260, help="warn above this absolute path length")
    ap.add_argument("--skip", action="append", help="directory name to skip (repeatable; default: "
                    + ", ".join(DEFAULT_SKIP) + ")")
    ap.add_argument("--strict", action="store_true", help="warnings also fail the run")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--version", action="version", version=f"portacheck {__version__}")
    args = ap.parse_args(argv)

    if not os.path.isdir(args.path):
        print(f"portacheck: not a directory: {args.path}", file=sys.stderr)
        return 2

    skip = tuple(args.skip) if args.skip is not None else DEFAULT_SKIP
    findings = scan_tree(args.path, max_path=args.max_path, skip=skip)
    errors = [f for f in findings if f.severity == "error"]
    warns = [f for f in findings if f.severity == "warn"]

    if args.json:
        print(json.dumps(
            {"path": os.path.abspath(args.path), "errors": len(errors), "warnings": len(warns),
             "findings": [f.as_dict() for f in findings]},
            indent=2))
    else:
        for f in findings:
            print(f"{f.severity.upper():5} {f.code:16} {f.path}: {f.detail}")
        verdict = "FAIL" if errors or (args.strict and warns) else "PASS"
        print(f"\n{len(errors)} error(s), {len(warns)} warning(s) — {verdict}")

    if errors:
        return 1
    return 1 if args.strict and warns else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
