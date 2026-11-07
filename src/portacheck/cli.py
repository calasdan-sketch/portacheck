"""portacheck CLI: scan a path and report portability hazards."""
from __future__ import annotations

import argparse
import fnmatch
import os
import sys
from typing import List

from . import __version__
from . import baseline as bl
from .fix import render_gitmv
from .output import RULES, render_github, render_json, render_sarif, render_text, safe
from .scan import (DEFAULT_MAX_PATH, DEFAULT_PREFIX_LEN, DEFAULT_SKIP, GitError, decode_nul_list,
                   git_added_paths, git_entries, new_path_set, scan_paths, walk_entries)


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
                         "backslash (default: %(default)s, e.g. C:\\Users\\jane.doe\\source\\repos\\project\\ is 39)")
    ap.add_argument("--skip", action="append", help="directory name to skip in a disk walk (repeatable; default: "
                    + ", ".join(DEFAULT_SKIP) + ")")
    ap.add_argument("--ignore", action="append", default=[], metavar="GLOB",
                    help="suppress findings whose path matches this glob, e.g. 'tests/fixtures/*' (repeatable)")
    ap.add_argument("--disable", action="append", default=[], metavar="CODE",
                    help="turn a check off by code, e.g. --disable symlink (repeatable; see --list-codes)")
    ap.add_argument("--list-codes", action="store_true", help="print every finding code and exit")
    ap.add_argument("--baseline", metavar="FILE", help="only report findings that are not in this baseline file")
    ap.add_argument("--write-baseline", metavar="FILE",
                    help="write today's findings to FILE as a baseline and exit 0")
    ap.add_argument("--new-since", metavar="REF",
                    help="with --git: only report findings on paths added since this git ref "
                         "(collisions with older files are still found)")
    ap.add_argument("--strict", action="store_true", help="warnings also fail the run")
    ap.add_argument("--format", choices=["text", "json", "github", "sarif", "gitmv"], default="text")
    ap.add_argument("--json", action="store_true", help="same as --format json")
    ap.add_argument("--allow-empty", action="store_true",
                    help="exit 0 when there is nothing to scan (default: exit 2, so a broken checkout cannot pass)")
    ap.add_argument("--version", action="version", version=f"portacheck {__version__}")
    args = ap.parse_args(argv)
    fmt = "json" if args.json else args.format
    if args.list_codes:
        for code, desc in RULES.items():
            print(f"{code:22} {desc}")
        return 0
    unknown = [c for c in args.disable if c not in RULES]
    if unknown:
        print(f"portacheck: unknown code(s) for --disable: {safe(', '.join(unknown))} (see --list-codes)",
              file=sys.stderr)
        return 2
    if args.new_since and not args.git:
        print("portacheck: --new-since needs --git", file=sys.stderr)
        return 2
    base = None
    if args.baseline:
        try:
            with open(args.baseline, encoding="utf-8") as fh:
                base = bl.loads(fh.read())
        except (OSError, bl.BaselineError) as e:
            print(f"portacheck: cannot use baseline {safe(args.baseline)}: {safe(str(e), False)}", file=sys.stderr)
            return 2
    for stream in (sys.stdout, sys.stderr):  # never crash on a cp1252 console
        try:
            stream.reconfigure(errors="backslashreplace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass

    symlinks = None
    on_disk = False
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
                paths, symlinks = git_entries(args.path)
            except GitError as e:
                print(f"portacheck: {safe(str(e), False)}", file=sys.stderr)
                return 2
        else:
            skip = tuple(args.skip) if args.skip is not None else DEFAULT_SKIP
            paths, symlinks = walk_entries(args.path, skip=skip)
            on_disk = True

    if not paths and not args.allow_empty:
        print("portacheck: nothing to scan (no paths found) — refusing to pass; "
              "use --allow-empty if that is expected", file=sys.stderr)
        return 2

    findings = scan_paths(paths, max_path=args.max_path, prefix_len=args.prefix_len,
                          symlinks=symlinks, on_disk=on_disk)
    if args.disable:
        findings = [f for f in findings if f.code not in args.disable]
    if args.new_since:
        try:
            fresh = new_path_set(paths, git_added_paths(args.path, args.new_since))
        except GitError as e:
            print(f"portacheck: {safe(str(e), False)}", file=sys.stderr)
            return 2
        findings = [f for f in findings if any(p in fresh for p in (f.paths or (f.path,)))]
    if args.ignore:
        findings = [f for f in findings
                    if not any(fnmatch.fnmatchcase(f.path, g) for g in args.ignore)]
    if args.write_baseline:
        try:
            with open(args.write_baseline, "w", encoding="utf-8") as fh:
                fh.write(bl.dumps(findings))
        except OSError as e:
            print(f"portacheck: cannot write baseline: {safe(str(e), False)}", file=sys.stderr)
            return 2
        print(f"portacheck: wrote {len(findings)} finding(s) to {safe(args.write_baseline)}", file=sys.stderr)
        return 0
    if base is not None:
        findings, suppressed, stale = bl.apply(findings, base)
        msg = f"portacheck: baseline hid {suppressed} existing finding(s)"
        if stale:
            msg += f"; {stale} baseline entr{'y' if stale == 1 else 'ies'} no longer match (regenerate it)"
        print(msg, file=sys.stderr)
    errors = [f for f in findings if f.severity == "error"]
    warns = [f for f in findings if f.severity == "warn"]

    if fmt == "json":
        print(render_json(findings, root, len(paths)))
    elif fmt == "sarif":
        print(render_sarif(findings, __version__))
    elif fmt == "gitmv":
        print(render_gitmv(paths, findings))
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
