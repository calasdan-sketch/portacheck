"""portacheck CLI: scan a path and report portability hazards."""
from __future__ import annotations

import argparse
import fnmatch
import os
import sys
from typing import List

from . import __version__
from .output import render_github, render_json, render_sarif, render_text, safe
from .scan import (DEFAULT_MAX_PATH, DEFAULT_PREFIX_LEN, DEFAULT_SKIP, GitError,
                   decode_nul_list, git_paths, scan_paths, walk_paths)


def _positive(v: str) -> int:
    n = int(v)
    if n < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return n


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="portacheck",
        description="Find repo paths that break Windows checkouts before Windows does.",
    )
    ap.add_argument("path", nargs="?", default=".", help="directory to scan (default: .)")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--git", action="store_true",
                     help="scan tracked + staged paths from the git index instead of walking the disk")
    src.add_argument("--stdin0", action="store_true",
                     help="read NUL-separated repo-relative paths from stdin (e.g. git ls-files -z)")
    ap.add_argument("--max-path", type=_positive, default=DEFAULT_MAX_PATH,
                    help="Windows MAX_PATH, counting the terminating NUL (default: %(default)s)")
    ap.add_argument("--prefix-len", type=_positive, default=DEFAULT_PREFIX_LEN,
                    help="assumed length of the Windows folder the repo is cloned into, with trailing "
                         "backslash (default: %(default)s, e.g. C:\\Users\\jane.doe\\source\\repos\\project\\ is 44)")
    ap.add_argument("--skip", action="append", help="directory name to skip in a disk walk (repeatable; default: "
                    + ", ".join(DEFAULT_SKIP) + ")")
    ap.add_argument("--ignore", action="append", default=[], metavar="GLOB",
                    help="suppress findings whose path matches this glob, e.g. 'tests/fixtures/*' (repeatable)")
    ap.add_argument("--strict", action="store_true", help="warnings also fail the run")
    ap.add_argument("--format", choices=["text", "json", "github", "sarif"], default="text")
    ap.add_argument("--json", action="store_true", help="same as --format json")
    ap.add_argument("--allow-empty", action="store_true",
                    help="exit 0 when there is nothing to scan (default: exit 2, so a broken checkout cannot pass)")
    ap.add_argument("--version", action="version", version=f"portacheck {__version__}")
    args = ap.parse_args(argv)
    fmt = "json" if args.json else args.format
    for stream in (sys.stdout, sys.stderr):  # never crash on a cp1252 console
        try:
            stream.reconfigure(errors="backslashreplace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass

    if args.stdin0:
        paths = decode_nul_list(sys.stdin.buffer.read())
        root = "<stdin>"
    else:
        if not os.path.isdir(args.path):
            print(f"portacheck: not a directory: {safe(args.path)}", file=sys.stderr)
            return 2
        root = os.path.abspath(args.path)
        if args.git:
            try:
                paths = git_paths(args.path)
            except GitError as e:
                print(f"portacheck: {safe(str(e), False)}", file=sys.stderr)
                return 2
        else:
            skip = tuple(args.skip) if args.skip is not None else DEFAULT_SKIP
            paths = walk_paths(args.path, skip=skip)

    if not paths and not args.allow_empty:
        print("portacheck: nothing to scan (no paths found) — refusing to pass; "
              "use --allow-empty if that is expected", file=sys.stderr)
        return 2

    findings = scan_paths(paths, max_path=args.max_path, prefix_len=args.prefix_len)
    if args.ignore:
        findings = [f for f in findings
                    if not any(fnmatch.fnmatchcase(f.path, g) for g in args.ignore)]
    errors = [f for f in findings if f.severity == "error"]
    warns = [f for f in findings if f.severity == "warn"]

    if fmt == "json":
        print(render_json(findings, root, len(paths)))
    elif fmt == "sarif":
        print(render_sarif(findings, __version__))
    elif fmt == "github":
        out = render_github(findings)
        if out:
            print(out)
        print(f"portacheck: {len(errors)} error(s), {len(warns)} warning(s) in {len(paths)} path(s)")
    else:
        print(render_text(findings, args.strict))

    if errors:
        return 1
    return 1 if args.strict and warns else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
