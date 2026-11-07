"""portacheck CLI: scan a path and report portability hazards."""
from __future__ import annotations

import argparse
import codecs
import errno
import fnmatch
import os
import sys
from typing import List, Optional

from . import __version__
from . import baseline as bl
from . import config as cfgmod
from .content import GITMODULES_MAX, gitmodules_findings
from .fix import render_gitmv
from .output import (EXPLAIN, RULES, explain, render_github, render_json, render_markdown, render_sarif,
                     render_text, safe)
from .scan import (DEFAULT_MAX_PATH, DEFAULT_PREFIX_LEN, DEFAULT_SKIP, GitError, decode_nul_list,
                   git_added_paths, git_snapshot, new_path_set, scan_paths, walk_entries)


def _positive(v: str) -> int:
    n = int(v)
    if n < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return n


def _max_path(v: str) -> int:
    n = int(v)
    if n < 2:  # 1 would leave no room for any name; 0 or less makes every path "too long"
        raise argparse.ArgumentTypeError("must be >= 2 (Windows MAX_PATH is 260)")
    return n


def _ascii_fallback(err: UnicodeError):
    """Console encoding (cp437, cp1252, ASCII) cannot show a character: use a plain look-alike or an escape."""
    bad = err.object[err.start:err.end]  # type: ignore[attr-defined]
    table = {"\u2014": "-", "\u2013": "-", "\u2192": "->", "\u2026": "...", "\u00d7": "x"}
    out = "".join(table.get(c) or c.encode("ascii", "backslashreplace").decode("ascii") for c in bad)
    return out, err.end  # type: ignore[attr-defined]


codecs.register_error("portacheck_console", _ascii_fallback)


def _err(msg: str) -> None:
    print(f"portacheck: {msg}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="portacheck",
        description="Find repo paths that break Windows and macOS checkouts, or attack them, before a clone does.",
        epilog="exit codes: 0 clean, 1 findings (warnings too with --strict), 2 the scan could not be done "
               "(not a directory or git repo, git missing, nothing to scan, bad settings or baseline file).\n"
               "examples:  portacheck --git   |   portacheck --rev origin/some-branch   |   "
               "portacheck --explain case_collision",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("path", nargs="?", default=".", help="directory to scan (default: .)")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--git", action="store_true",
                     help="scan the whole git index (tracked + staged paths) instead of walking the disk")
    src.add_argument("--rev", metavar="REF",
                     help="scan the tree of a commit, branch or tag without checking it out (e.g. a PR head)")
    src.add_argument("--stdin0", action="store_true",
                     help="read NUL-separated repo-relative paths from stdin (e.g. git ls-files -z)")
    ap.add_argument("--max-path", type=_max_path, default=None,
                    help=f"Windows MAX_PATH, counting the terminating NUL (default: {DEFAULT_MAX_PATH})")
    ap.add_argument("--prefix-len", type=_positive, default=None,
                    help="assumed length of the Windows folder the repo is cloned into, with trailing "
                         f"backslash (default: {DEFAULT_PREFIX_LEN}, e.g. C:\\Users\\jane.doe\\source\\repos\\project\\ is 39)")
    ap.add_argument("--skip", action="append", help="directory name to skip in a disk walk (repeatable; default: "
                    + ", ".join(DEFAULT_SKIP) + ")")
    ap.add_argument("--ignore", action="append", default=[], metavar="GLOB",
                    help="suppress findings whose path matches this glob, e.g. 'tests/fixtures/*' (repeatable)")
    ap.add_argument("--disable", action="append", default=[], metavar="CODE",
                    help="turn a check off by code, e.g. --disable symlink (repeatable; see --list-codes)")
    ap.add_argument("--list-codes", action="store_true", help="print every finding code and exit")
    ap.add_argument("--explain", metavar="CODE", help="say why a finding matters and how to fix it, then exit")
    ap.add_argument("--config", metavar="FILE",
                    help="settings file to trust (default: .portacheck.toml or [tool.portacheck] in pyproject.toml "
                         "in the scanned folder, which may not switch off attack checks)")
    ap.add_argument("--no-config", action="store_true", help="do not look for a settings file")
    ap.add_argument("--baseline", metavar="FILE", help="only report findings that are not in this baseline file")
    ap.add_argument("--write-baseline", metavar="FILE",
                    help="write today's findings to FILE as a baseline and exit 0")
    ap.add_argument("--new-since", metavar="REF",
                    help="with --git: only report findings on paths added since this git ref "
                         "(collisions with older files are still found)")
    ap.add_argument("--strict", action="store_true", help="warnings also fail the run")
    ap.add_argument("--format", choices=["text", "json", "github", "sarif", "gitmv", "markdown"], default="text")
    ap.add_argument("--json", action="store_true", help="same as --format json")
    ap.add_argument("--allow-empty", action="store_true",
                    help="exit 0 when there is nothing to scan (default: exit 2, so a broken checkout cannot pass)")
    ap.add_argument("--version", action="version", version=f"portacheck {__version__}")
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    """Exit codes: 0 clean, 1 findings, 2 the scan could not be done (including any internal error: fail closed)."""
    try:
        return _main(argv)
    except BrokenPipeError:
        return _quiet_exit()
    except OSError as e:
        if e.errno in (errno.EPIPE, errno.EINVAL) and os.name == "nt":  # Windows reports a closed pipe this way
            return _quiet_exit()
        _err(f"internal error (OSError): {safe(str(e)[:300], False)} — nothing was verified, failing closed")
        return 2
    except KeyboardInterrupt:
        return 130
    except Exception as e:  # never let a crash look like "findings" (exit 1) or like a pass
        _err(f"internal error ({type(e).__name__}): {safe(str(e)[:300], False)} — nothing was verified, failing closed")
        return 2


def _quiet_exit() -> int:
    """The reader of our output went away (for example `| head`): stop quietly, without a traceback."""
    try:
        sys.stdout = open(os.devnull, "w")
    except OSError:
        pass
    return 2


def _gitmodules_from_disk(root: str) -> Optional[bytes]:
    p = os.path.join(root, ".gitmodules")
    if os.path.islink(p) or not os.path.isfile(p):
        return None
    with open(p, "rb") as fh:
        return fh.read(GITMODULES_MAX + 1)


def _main(argv: Optional[List[str]]) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    fmt = "json" if args.json else args.format
    if args.list_codes:
        for code, desc in RULES.items():
            print(f"{code:22} {desc}")
        return 0
    if args.explain is not None:
        if args.explain not in EXPLAIN:
            _err(f"unknown code {safe(args.explain)} (see --list-codes)")
            return 2
        print(explain(args.explain))
        return 0
    if args.new_since and not args.git:
        _err("--new-since needs --git")
        return 2
    if not os.path.isdir(args.path) and not args.stdin0:
        _err(f"not a directory: {safe(args.path)}")
        return 2

    cfg: Optional[cfgmod.Config] = None
    try:
        if args.config:
            cfg = cfgmod.load(args.config, trusted=True)
        elif not args.no_config and os.path.isdir(args.path):
            cfg = cfgmod.discover(args.path)
            if cfg is not None:
                cfgmod.check_trust(cfg)
    except cfgmod.ConfigError as e:
        _err(f"settings file: {safe(str(e), False)}")
        return 2
    if cfg is not None:
        _err(f"using settings from {safe(cfg.path)}" + ("" if cfg.trusted else " (found in the scanned folder)"))
    cv = cfg.values if cfg else {}

    disable = list(dict.fromkeys(list(args.disable) + list(cv.get("disable", []))))
    unknown = [c for c in disable if c not in RULES]
    if unknown:
        _err(f"unknown code(s) for --disable: {safe(', '.join(unknown))} (see --list-codes)")
        return 2
    max_path = args.max_path if args.max_path is not None else cv.get("max_path", DEFAULT_MAX_PATH)
    prefix_len = args.prefix_len if args.prefix_len is not None else cv.get("prefix_len", DEFAULT_PREFIX_LEN)
    strict = args.strict or bool(cv.get("strict", False))
    allow_empty = args.allow_empty or bool(cv.get("allow_empty", False))
    skip_opt = args.skip if args.skip is not None else cv.get("skip")
    trusted_cfg = cfg is None or cfg.trusted

    base = None
    if args.baseline:
        try:
            with open(args.baseline, encoding="utf-8-sig") as fh:
                base = bl.loads(fh.read())
        except (OSError, UnicodeDecodeError, bl.BaselineError) as e:
            _err(f"cannot use baseline {safe(args.baseline)}: {safe(getattr(e, 'strerror', None) or str(e), False)}")
            return 2
    for stream in (sys.stdout, sys.stderr):  # never crash on a cp1252 console
        try:
            stream.reconfigure(errors="portacheck_console")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    try:  # Windows would write \r\n: that breaks a `--format gitmv > fix.sh` script and hashes of the output
        sys.stdout.reconfigure(newline="\n")  # type: ignore[attr-defined]
    except (AttributeError, ValueError, OSError):
        pass

    symlinks = None
    on_disk = False
    gitmodules: Optional[bytes] = None
    if args.stdin0:
        raw = sys.stdin.buffer.read()
        if b"\0" not in raw and b"\n" in raw.strip(b"\n"):
            _err("the input has newlines but no NUL separators: did you forget -z / use a NUL-separated list? "
                 "(a newline is a legal file-name character, so it is not treated as a separator)")
        paths = decode_nul_list(raw)
        root = "<stdin>"
    else:
        root = os.path.abspath(args.path)
        if args.git or args.rev is not None:
            try:
                snap = git_snapshot(args.path, args.rev)
            except GitError as e:
                _err(safe(str(e), False))
                return 2
            paths, symlinks, gitmodules = snap.paths, snap.symlinks, snap.gitmodules
        else:
            skip = tuple(skip_opt) if skip_opt is not None else DEFAULT_SKIP
            walk_errors: List[str] = []
            paths, symlinks = walk_entries(args.path, skip=skip, errors=walk_errors)
            on_disk = True
            if walk_errors:
                _err(f"{len(walk_errors)} folder(s) could not be read, so the scan would be incomplete — "
                     f"failing closed (first: {safe(walk_errors[0])})")
                return 2
            gitmodules = _gitmodules_from_disk(args.path)

    if not paths and not allow_empty:
        _err("nothing to scan (no paths found) — refusing to pass; use --allow-empty if that is expected")
        return 2

    findings = scan_paths(paths, max_path=max_path, prefix_len=prefix_len, symlinks=symlinks, on_disk=on_disk)
    if gitmodules is not None:
        findings.extend(gitmodules_findings(gitmodules))
        findings.sort(key=lambda f: (f.severity != "error", f.code, f.path))
    if disable:
        findings = [f for f in findings if f.code not in disable]
    if args.new_since:
        try:
            fresh = new_path_set(paths, git_added_paths(args.path, args.new_since))
        except GitError as e:
            _err(safe(str(e), False))
            return 2
        findings = [f for f in findings if any(p in fresh for p in (f.paths or (f.path,)))]
    ignore_globs = [(g, True) for g in args.ignore] + [(g, trusted_cfg) for g in cv.get("ignore", [])]
    if ignore_globs:
        used = set()
        refused = set()

        def ignored(f) -> bool:
            for g, may_hide_attacks in ignore_globs:
                if not may_hide_attacks and f.code in cfgmod.PROTECTED:
                    if fnmatch.fnmatchcase(f.path, g):
                        refused.add(g)  # a settings file found in the scanned folder cannot hide these
                    continue
                if fnmatch.fnmatchcase(f.path, g):
                    used.add(g)
                    return True
            return False

        findings = [f for f in findings if not ignored(f)]
        for g in sorted(refused):
            _err(f"ignore pattern {safe(g)} from the settings file may not hide attack-related findings "
                 "(use --ignore on the command line, or --config to name a file you trust)")
        for g, _ in ignore_globs:
            if g not in used and g not in refused:
                _err(f"ignore pattern {safe(g)} matched no finding (stale?)")
    if args.write_baseline:
        try:
            bl.write_atomic(args.write_baseline, bl.dumps(findings))
        except OSError as e:
            _err(f"cannot write baseline {safe(args.write_baseline)}: {safe(e.strerror or str(e), False)}")
            return 2
        _err(f"wrote {len(findings)} finding(s) to {safe(args.write_baseline)}")
        return 0
    if base is not None:
        findings, suppressed, stale = bl.apply(findings, base)
        msg = f"baseline hid {suppressed} existing finding(s)"
        if stale:
            msg += f"; {stale} baseline entr{'y' if stale == 1 else 'ies'} no longer match (regenerate it)"
        _err(msg)
    errors = [f for f in findings if f.severity == "error"]
    warns = [f for f in findings if f.severity == "warn"]

    if fmt == "json":
        print(render_json(findings, root, len(paths)))
    elif fmt == "sarif":
        print(render_sarif(findings, __version__))
    elif fmt == "gitmv":
        print(render_gitmv(paths, findings))
    elif fmt == "markdown":
        print(render_markdown(findings, len(paths), strict))
    elif fmt == "github":
        out = render_github(findings)
        if out:
            print(out)
        print(f"portacheck: {len(errors)} error(s), {len(warns)} warning(s) in {len(paths)} path(s)")
    else:
        print(render_text(findings, strict))

    if errors:
        return 1
    return 1 if strict and warns else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
