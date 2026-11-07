#!/usr/bin/env python3
"""Reproducible benchmark: detection precision/recall on a generated corpus, and speed on 500k paths.

    python benchmarks/bench.py                    # accuracy + speed, prints Markdown
    python benchmarks/bench.py --old-src DIR      # also score an older portacheck (DIR contains portacheck/)
    python benchmarks/bench.py --files 500000     # corpus size for the speed test

Labels come from how each case is *constructed* (a name built from a known
Windows/macOS/Git rule is hostile; an ordinary name is benign), never from the
output of any tool. Comparators:

* ``pre-commit regex``: the ``files:`` regex of pre-commit-hooks'
  ``check-illegal-windows-names``, copied verbatim (pre-commit-hooks main, .pre-commit-hooks.yaml).
* ``pre-commit case``: the logic of pre-commit-hooks' ``check-case-conflict`` (lower() compare, folders included).
* ``git protectNTFS+HFS``: real ``git update-index --cacheinfo`` with core.protectNTFS/protectHFS on.
  Git only guards its own metadata (.git); it is listed so the table shows what Git already covers.
"""
from __future__ import annotations

import argparse
import os
import random
import re
import resource
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "src"))

# ---- comparators --------------------------------------------------------------------------------------
# pre-commit-hooks main: .pre-commit-hooks.yaml, id check-illegal-windows-names, `files:`
PRECOMMIT_RE = re.compile(r'(?i)((^|/)(CON|PRN|AUX|NUL|COM[\d¹²³]|LPT[\d¹²³])(\.|/|$)|[<>:\"\\|?*\x00-\x1F]|/[^/]*[\.\s]/|[^/]*[\.\s]$)')  # noqa: E501


def precommit_regex(case):
    return any(PRECOMMIT_RE.search(p) for p in case["paths"])


def precommit_case(case):
    """check-case-conflict: names (files and every parent folder) equal after lower()."""
    files = set(case["paths"])
    dirs = set()
    for f in files:
        parts = f.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add("/".join(parts[:i]))
    allp = files | dirs
    return len({p.lower() for p in allp}) != len(allp)


def git_rejects(case, tmp):
    """True if real git refuses any path of the case (each case gets an empty index)."""
    sha = subprocess.run(["git", "-C", tmp, "hash-object", "-w", "--stdin"], input=b"x\n",
                         stdout=subprocess.PIPE, check=True).stdout.strip().decode()
    env = dict(os.environ, GIT_INDEX_FILE=os.path.join(tmp, "bench-index"))
    if os.path.exists(env["GIT_INDEX_FILE"]):
        os.remove(env["GIT_INDEX_FILE"])
    for p in case["paths"]:
        r = subprocess.run(["git", "-C", tmp, "-c", "core.protectNTFS=true", "-c", "core.protectHFS=true",
                            "update-index", "--add", "--cacheinfo", f"100644,{sha},{p}"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        if r.returncode != 0:
            return True
    return False


# ---- corpus ---------------------------------------------------------------------------------------------
NFD = lambda s: unicodedata.normalize("NFD", s)  # noqa: E731
DEV = ["CON", "PRN", "AUX", "NUL"] + [f"COM{i}" for i in range(1, 10)] + [f"LPT{i}" for i in range(1, 10)]


def hostile_cases(rnd):
    cases = []

    def add(cat, paths, symlinks=None):
        cases.append({"cat": cat, "paths": paths, "symlinks": symlinks, "hostile": True})

    for d in DEV:
        for form in ("{}", "{}.txt", "{}.tar.gz", "{} .txt", "{}  .md", "{}:stream"):
            n = form.format(rnd.choice([d, d.lower(), d.capitalize()]))
            add("reserved name", [rnd.choice(["", "src/", "a/b/", "docs/"]) + n])
        add("reserved name", [f"{d}/inner.txt"])  # as a folder
    for n in ("COM\u00b9", "LPT\u00b2.log", "CONIN$", "CONOUT$.txt", "LPT0"):
        add("reserved name", ["x/" + n])
    for c in '<>:"|?*\\':
        add("invalid character", [f"dir/na{c}me.txt"])
    for o in (1, 7, 31):
        add("invalid character", ["dir/na" + chr(o) + "me.txt"])
    for ext in (".", " ", ". ", " .", "..", "  "):
        add("trailing dot/space", [f"dir/name{ext}"])
        add("trailing dot/space", [f"dir{ext}/file.txt"])
    for stem in ("Config", "README", "Index", "Makefile", "Dockerfile", "Data"):
        add("case collision", [f"src/{stem}.md", f"src/{stem.lower()}.md"])
        add("case collision", [f"{stem}/a.txt", f"{stem.lower()}/b.txt"])
        add("case collision", [f"x/{stem}.MD", f"x/{stem}.md"])
    for stem in ("caf\u00e9", "na\u00efve", "\u00fcber", "se\u00f1or", "\u00e5ngstr\u00f6m", "\u0105\u0107\u0119"):
        add("unicode (NFC/NFD) collision", [f"i18n/{stem}.txt", f"i18n/{NFD(stem)}.txt"])
        add("unicode (NFC/NFD) collision", [f"i18n/{stem}.txt", f"i18n/{NFD(stem).upper()}.txt"])
    add("component > 255", ["x/" + "a" * 256 + ".txt"])
    add("component > 255", ["x/" + "\U0001F600" * 128])
    add("component > 255", ["x/" + "n" * 300])
    for i in range(6):
        add("path > MAX_PATH", ["/".join(["d" * (30 + i * 3)] * 7) + "/file.txt"])
    # git-metadata tricks (labelled by construction from path.c's documented synonyms of .git)
    for n in (".git", ".GIT", ".git ", ".git.", ".git . .", ".git...", "git~1", "GIT~1", "git~1.",
              ".git::$INDEX_ALLOCATION", ".git:x", ".g\u200cit", ".\u200egit", ".gi\ufefft", ".GIT\u202e", "x\\.git"):
        add("Git-dir alias (.git tricks)", [f"{n}/hooks/post-checkout"])
        add("Git-dir alias (.git tricks)", [f"sub/{n}/config"])
    for n in (".GitModules", ".gitmodules ", "GITMOD~1", "gi7eba~1", ".GITATTRIBUTES", "gitatt~1", "gi7d29~1",
              ".g\u200citmodules"):
        add("Git-meta alias (.gitmodules...)", [f"{n}"])
    for stem in ("longfilename", "documentation", "readme_first", "configuration"):
        add("8.3 short-name clash", [f"d/{stem}.txt", f"d/{stem[:6].upper()}~1.TXT"])
    for t in ("../../etc/passwd", "/etc/passwd", "C:\\Windows", "a\\b"):
        add("risky symlink", ["links/l"], symlinks={"links/l": t})
    add("risky symlink", ["a/.gitmodules"], symlinks={"a/.gitmodules": "x"})
    add("risky symlink", ["lnk", "lnk/inner"], symlinks={"lnk": "elsewhere"})
    for n in ("invoice\u202egpj.exe", "re\u202epdf.txt", "a\u200bb.py", "x\u2066y.js", "doc\ufeff.txt", "t\u200dr.md"):
        add("invisible/bidi (Trojan Source)", ["files/" + n])
    for n in ("\u3042" * 100, "\u00e9" * 130, "\U0001F600" * 100):
        add("name > 255 bytes (Linux NAME_MAX)", ["assets/" + n + ".png"])
    for a, b in (("README.md", "R\u0415ADME.md"), ("file.txt", "\ufb01le.txt"), ("abc.txt", "\uff41\uff42\uff43.txt"),
                 ("config.yml", "c\u043enfig.yml"), ("main.py", "m\u0430in.py"), ("OPEN.md", "\u039fPEN.md")):
        add("look-alike names", ["src/" + a, "src/" + b])
    add("look-alike names", ["src/p\u0430ypal.js"])  # one word mixing Latin and Cyrillic
    add("look-alike names", ["src/\u03bfauth.js"])
    return cases


BENIGN_FIXED = [
    ".github/workflows/ci.yml", ".gitignore", ".gitattributes", ".gitmodules", ".gitkeep", ".github/CODEOWNERS",
    ".gitlab-ci.yml", "console.log", "docs/COM10.txt", "AUXILIARY.md", "src/nullable.py", "lib/prn_utils.py",
    "lpt/readme.md", "con-sole/x", "a.b.c.d", "file (1).txt", "v1.0.0/notes.md", "legit/x", "digit.txt",
    "gitmodules.txt", "git.md", "src/git/hooks.py", "mailmap", ".mailmap", "gimp~1x", "Makefile", "LICENSE",
    "src/\u00e9t\u00e9.txt", "i18n/\u65e5\u672c\u8a9e.txt", "emoji/\U0001F600.png", "stra\u00dfe.txt",  # NFC names
    "node_modules/.bin/tsc", "build/out/app.js", "a/b/c/d/e/f/g.txt", "x" * 100 + ".txt", "name-with_many+chars=ok,1;2.txt",
    "docs/Config.json", "src/config.json", "tests/fixtures/CON_.txt", "this is fine.txt", "UPPER.TXT", "lower.txt",
    "a/.hidden", "..data/x", "@types/node/index.d.ts", "~tilde/x", "100%/x", "#id/x", "{braces}/x", "a&b.txt",
    "src/test~backup.txt", "src/PROGRA~1.txt", "docs/short~1.md",
    "i18n/\u039a\u03b1\u03bb\u03ac\u03c2-report.txt", "i18n/\u041f\u0440\u0438\u0432\u0435\u0442.md",   # Greek / Cyrillic only
    "docs/report-\u041f\u0440\u0438\u0432\u0435\u0442.md", "math/\u03c0R.txt", "i18n/" + "\u3042" * 80 + ".txt",
    "assets/" + "\u00e9" * 100 + ".png", "src/\u00fcber-caf\u00e9.js",
]
# these pairs are NOT collisions on NTFS/macOS even though they look alike
BENIGN_PAIRS = [
    ["a/stra\u00dfe.txt", "a/strasse.txt"],               # ß is not folded to ss by NTFS
    ["src/Config.json", "docs/config.json"],              # different folders
    ["a/readme.md", "b/README.md"],
    ["pkg/Makefile", "pkg/Makefile.in"],
    ["x/file1.txt", "x/file2.txt"],
    ["d/longfilename.txt", "d/LONGFI~1.PNG"],             # different extension: no short-name clash
    ["d/short.txt", "d/SHORT~1.TXT"],                     # 8.3-compliant name has no alias
    ["lib/\u00e9.txt", "lib/e.txt"],
    ["i18n/\u041f\u0440\u0438\u0432\u0435\u0442.md", "i18n/\u03a0\u03c1\u03bf.md"],  # two different non-Latin words
    ["a/caf\u00e9.txt", "a/cafe.txt"],
]


def benign_cases(rnd, n_random):
    cases = [{"cat": "benign", "paths": [p], "symlinks": None, "hostile": False} for p in BENIGN_FIXED]
    cases += [{"cat": "benign", "paths": list(p), "symlinks": None, "hostile": False} for p in BENIGN_PAIRS]
    cases.append({"cat": "benign", "paths": ["docs/guide.md", "docs/img/a.png"], "hostile": False,
                  "symlinks": {"docs/guide.md": "../README.md"}})  # in-repo link: only the Windows-privilege note
    alpha = "abcdefghijklmnopqrstuvwxyz0123456789_-"
    for _ in range(n_random):
        depth = rnd.randint(1, 4)
        parts = ["".join(rnd.choice(alpha) for _ in range(rnd.randint(3, 14))) for _ in range(depth)]
        parts[-1] += rnd.choice([".py", ".js", ".md", ".txt", ".json", ""])
        p = "/".join(parts)
        if PRECOMMIT_RE.search(p) or re.search(r"(^|/)(con|prn|aux|nul|com\d|lpt\d)(\.|/|$)", p, re.I):
            continue
        cases.append({"cat": "benign", "paths": [p], "symlinks": None, "hostile": False})
    return cases


# ---- scoring --------------------------------------------------------------------------------------------
def load_portacheck(src_dir):
    """Import portacheck from ``src_dir`` in a clean module namespace."""
    for m in [m for m in sys.modules if m == "portacheck" or m.startswith("portacheck.")]:
        del sys.modules[m]
    sys.path.insert(0, src_dir)
    try:
        import portacheck.scan as scan
        return scan
    finally:
        sys.path.remove(src_dir)


def portacheck_detector(scan, errors_only=False):
    def det(case):
        kw = {}
        if case.get("symlinks") is not None and "symlinks" in scan.scan_paths.__code__.co_varnames:
            kw["symlinks"] = case["symlinks"]
        f = scan.scan_paths(case["paths"], **kw)
        if errors_only:
            f = [x for x in f if x.severity == "error"]
        # a plain "tracked symlink" note is informational, not a hazard verdict
        f = [x for x in f if not (x.code == "symlink" and case["cat"] == "benign")]
        return bool(f)
    return det


def score(det, cases):
    tp = fp = fn = tn = 0
    per = {}
    for c in cases:
        hit = det(c)
        if c["hostile"]:
            tp += hit
            fn += not hit
            r = per.setdefault(c["cat"], [0, 0])
            r[0] += hit
            r[1] += 1
        else:
            fp += hit
            tn += not hit
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": prec, "recall": rec, "f1": f1, "per": per}


# ---- speed ----------------------------------------------------------------------------------------------
def make_paths(n_files, seed=1):
    """A repo-shaped tree: ~n/15 folders, mixed depth, common extensions."""
    rnd = random.Random(seed)
    words = ["src", "lib", "core", "utils", "app", "tests", "docs", "assets", "img", "components", "pkg", "vendor",
             "internal", "cmd", "api", "models", "views", "static", "config", "scripts"]
    dirs = [""]
    for _ in range(max(1, n_files // 15)):
        parent = rnd.choice(dirs)
        dirs.append((parent + "/" if parent else "") + rnd.choice(words) + str(rnd.randint(0, 99)))
    dirs = dirs[1:]
    exts = [".py", ".js", ".ts", ".md", ".png", ".json", ".go", ".rs", ".css", ".html"]
    return [f"{rnd.choice(dirs)}/file_{i}{rnd.choice(exts)}" for i in range(n_files)]


def time_scan(src_dir, paths_file, runs):
    """Wall time of `portacheck --stdin0` in a fresh process (startup included) + peak RSS of that process."""
    code = ("import sys; sys.path.insert(0, %r); from portacheck.cli import main; sys.exit(main(['--stdin0']))" % src_dir)
    best, rss = [], 0
    for _ in range(runs):
        with open(paths_file, "rb") as fh:
            t = time.perf_counter()
            p = subprocess.run([sys.executable, "-c", code], stdin=fh, stdout=subprocess.DEVNULL)
            best.append(time.perf_counter() - t)
        if p.returncode not in (0, 1):
            raise SystemExit(f"scan failed rc={p.returncode}")
        rss = max(rss, resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss // 1024)
    return statistics.median(best), min(best), rss


def time_precommit(paths, runs):
    cs = []
    for _ in range(runs):
        t = time.perf_counter()
        _ = [p for p in paths if PRECOMMIT_RE.search(p)]
        cs.append(time.perf_counter() - t)
    cs2 = []
    for _ in range(runs):
        t = time.perf_counter()
        files = set(paths)
        dirs = set()
        for f in files:
            parts = f.split("/")[:-1]
            for i in range(1, len(parts) + 1):
                dirs.add("/".join(parts[:i]))
        allp = files | dirs
        _ = len({p.lower() for p in allp}) != len(allp)
        cs2.append(time.perf_counter() - t)
    return statistics.median(cs), statistics.median(cs2)


def git_parity(n, seed, scan):
    """Random names built from the pieces of Git's `.git` synonyms, scored against real git as ground truth.
    Backslash is left out on purpose: portacheck flags any name containing one (it is a separator on
    Windows), while a Linux git only objects when it follows `.git`."""
    pieces = [".", "g", "G", "i", "I", "t", "T", "~", "1", "2", " ", "\u200c", "\ufeff", "\u202e", ":", "$", "x",
              "git", "GIT", ".git", "~1", "::$INDEX_ALLOCATION"]
    rnd = random.Random(seed)
    tmp = tempfile.mkdtemp(prefix="pcparity-")
    subprocess.run(["git", "init", "-q", tmp], check=True)
    tp = fp = fn = tn = 0
    for _ in range(n):
        if rnd.random() < 0.5:  # near-misses and real synonyms: mutate a true synonym
            base = list(rnd.choice([".git", "git~1", ".GiT", "GIT~1", ".git", "git~2", ".gitx"]))
            for _ in range(rnd.randint(0, 2)):
                base.insert(rnd.randint(0, len(base)), rnd.choice(["\u200c", "\u202e", "\ufeff", "x", " ", "."]))
            name = "".join(base) + "".join(rnd.choice(" .:$x") for _ in range(rnd.randint(0, 3)))
        else:
            name = "".join(rnd.choice(pieces) for _ in range(rnd.randint(1, 6)))
        if name in (".", ".."):
            continue
        case = {"paths": [name + "/x"]}
        truth = git_rejects(case, tmp)
        ours = any(f.code == "git_dir_alias" for f in scan.scan_paths(case["paths"]))
        tp += truth and ours
        fn += truth and not ours
        fp += ours and not truth
        tn += (not truth) and (not ours)
    shutil.rmtree(tmp, ignore_errors=True)
    return tp, fp, fn, tn


# ---- .gitmodules vs git fsck ----------------------------------------------------------------------------
def gitmodules_cases(n, seed):
    rnd = random.Random(seed)
    # roughly 2 in 3 values are ordinary, so most files are clean and most hostile ones have one bad field
    names = ["a", "lib/x", "vendor/some-lib", "a..b", "sub module", "UPPER", "docs/x.y"] * 2 + [
        "../evil", "a/../b", "x\\\\..\\\\y", "..", "a/..", "../../x"]
    urls = ["https://h/x.git", "ssh://git@h/x", "../rel", "./sibling", "file:///tmp/x", "git://h/x", "https://h/a%20b"] * 2 + [
        "-oProxyCommand=id", "./%0a", "git://h/%0ax", "ext::sh -c id", '"-q"', "-", "https://h/%0Ax", "--upload-pack=x"]
    paths = ["a", "lib/x", "dir/sub", "../up", "a.b", "sub/dir"] * 2 + ["-x", "--help"]
    updates = [None, None, None, None, "merge", "checkout", "rebase", "none", "!id", "! id"]
    out = []
    for _ in range(n):
        body = ""
        for _ in range(rnd.randint(1, 3)):
            u = rnd.choice(updates)
            body += (f'[submodule "{rnd.choice(names)}"]\n\tpath = {rnd.choice(paths)}\n'
                     f'\turl = {rnd.choice(urls)}\n' + (f"\tupdate = {u}\n" if u else ""))
        out.append(body)
    return out


def gitmodules_parity(n, seed, content):
    """Per random .gitmodules: does `git fsck --strict` complain, and does portacheck report an error?"""
    tp = fp = fn = tn = 0
    warn_only = 0
    with tempfile.TemporaryDirectory(prefix="pcgm-") as td:
        for i, body in enumerate(gitmodules_cases(n, seed)):
            d = os.path.join(td, str(i))
            subprocess.run(["git", "init", "-q", d], check=True)
            env = dict(os.environ, GIT_AUTHOR_NAME="b", GIT_AUTHOR_EMAIL="b@x.invalid", GIT_COMMITTER_NAME="b",
                       GIT_COMMITTER_EMAIL="b@x.invalid", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
            sha = subprocess.run(["git", "-C", d, "hash-object", "-w", "--stdin"], input=body.encode(),
                                 stdout=subprocess.PIPE, check=True, env=env).stdout.strip().decode()
            tree = subprocess.run(["git", "-C", d, "mktree"], input=f"100644 blob {sha}\t.gitmodules\n".encode(),
                                  stdout=subprocess.PIPE, check=True, env=env).stdout.strip().decode()
            com = subprocess.run(["git", "-C", d, "commit-tree", tree, "-m", "x"], stdout=subprocess.PIPE,
                                 check=True, env=env).stdout.strip().decode()
            subprocess.run(["git", "-C", d, "update-ref", "refs/heads/main", com], check=True, env=env)
            r = subprocess.run(["git", "-C", d, "fsck", "--strict"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               env=env)
            git_says = b"gitmodules" in r.stdout
            f = content.gitmodules_findings(body.encode())
            ours = any(x.severity == "error" or x.code == "submodule_config" for x in f)
            warn_only += (not ours) and bool(f)
            tp += git_says and ours
            fp += ours and not git_says
            fn += git_says and not ours
            tn += (not git_says) and not ours
    return tp, fp, fn, tn, warn_only


def robustness(src_dir, depth):
    """One path with `depth` components in a fresh process: seconds, that process's own peak RSS (MB), exit code."""
    code = ("import sys, resource; sys.path.insert(0, %r); from portacheck.scan import scan_paths; "
            "scan_paths(['a/' * %d + 'x']); print(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024)"
            % (src_dir, depth))
    t = time.perf_counter()
    r = subprocess.run([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    dt = time.perf_counter() - t
    try:
        rss = int(r.stdout.split()[-1])
    except (ValueError, IndexError):
        rss = -1
    return dt, rss, r.returncode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--old-src", help="directory containing an older portacheck package to compare")
    ap.add_argument("--prev-src", help="directory containing the previous round's portacheck package")
    ap.add_argument("--files", type=int, default=500_000)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--seed", type=int, default=20261107)
    ap.add_argument("--no-speed", action="store_true")
    ap.add_argument("--parity", type=int, default=3000, help="random names for the git-parity check (0 = skip)")
    args = ap.parse_args()

    rnd = random.Random(args.seed)
    cases = hostile_cases(rnd) + benign_cases(rnd, 2000)
    nh = sum(c["hostile"] for c in cases)
    print(f"## Accuracy: {nh} hostile cases, {len(cases) - nh} benign cases (seed {args.seed})\n")

    tools = {}
    new = load_portacheck(os.path.join(os.path.dirname(HERE), "src"))
    import portacheck.content as new_content  # noqa: E402  (the tree under test, before older trees replace it)
    tools["portacheck (this tree)"] = portacheck_detector(new)
    if args.old_src:
        old = load_portacheck(args.old_src)
        tools["portacheck 0.2.0"] = portacheck_detector(old)
    if args.prev_src:
        prev = load_portacheck(args.prev_src)
        tools["portacheck 0.3.0 @ round 2"] = portacheck_detector(prev)
    tools["pre-commit regex (illegal names)"] = precommit_regex
    tools["pre-commit case-conflict"] = precommit_case
    if shutil.which("git"):
        tmp = tempfile.mkdtemp(prefix="pcbench-")
        subprocess.run(["git", "init", "-q", tmp], check=True)
        tools["git protectNTFS+HFS"] = lambda c, _t=tmp: git_rejects(c, _t)
    results = {name: score(det, cases) for name, det in tools.items()}

    print("| tool | precision | recall | F1 | false positives | missed |")
    print("|---|---|---|---|---|---|")
    for name, r in results.items():
        print(f"| {name} | {r['precision']:.3f} | {r['recall']:.3f} | {r['f1']:.3f} | {r['fp']} | {r['fn']} |")
    cats = []
    for c in cases:
        if c["hostile"] and c["cat"] not in cats:
            cats.append(c["cat"])
    print("\nRecall by hazard class (caught / cases):\n")
    print("| hazard | " + " | ".join(results) + " |")
    print("|---|" + "---|" * len(results))
    for cat in cats:
        row = []
        for r in results.values():
            a, b = r["per"].get(cat, [0, 0])
            row.append(f"{a}/{b}")
        print(f"| {cat} | " + " | ".join(row) + " |")

    if shutil.which("git") and args.parity:
        tp, fp, fn, tn = git_parity(args.parity, args.seed, new)
        print(f"\n## Git parity (ground truth = real git with core.protectNTFS/protectHFS): {args.parity:,} random "
              f"`.git`-synonym names\n\n| git rejects & portacheck flags | portacheck only | git only | both clean |\n"
              f"|---|---|---|---|\n| {tp} | {fp} | {fn} | {tn} |")

    if shutil.which("git") and args.parity:
        n = min(args.parity, 400)
        tp, fp, fn, tn, wo = gitmodules_parity(n, args.seed, new_content)
        print(f"\n## .gitmodules (ground truth = `git fsck --strict`): {n} random files\n\n"
              f"| git complains & portacheck errors | portacheck only | git only | both clean |\n|---|---|---|---|\n"
              f"| {tp} | {fp} | {fn} | {tn} |\n\n(of the {tn} both-clean files, {wo} got a portacheck warning, "
              f"e.g. the `ext::` transport, which Git's fsck does not check.)")

    if not args.no_speed:
        print("\n## Robustness: one hostile path with 3,000 components (fresh process each)\n")
        print("| tool | seconds | peak RSS MB | exit |\n|---|---|---|---|")
        rb = [("portacheck (this tree)", os.path.join(os.path.dirname(HERE), "src"))]
        if args.prev_src:
            rb.append(("portacheck 0.3.0 @ round 2", args.prev_src))
        for name, src_dir in rb:
            dt, rss, rc = robustness(src_dir, 3000)
            print(f"| {name} | {dt:.2f} | {rss} | {rc} |")

    if not args.no_speed:
        paths = make_paths(args.files)
        with tempfile.TemporaryDirectory() as td:
            pf = os.path.join(td, "paths.bin")
            with open(pf, "wb") as fh:
                fh.write(("\0".join(paths) + "\0").encode())
            print(f"\n## Speed: {args.files:,} tracked files, {len({p.rsplit('/', 1)[0] for p in paths}):,} folders "
                  f"(fresh process incl. start-up; median of {args.runs}; Python {sys.version.split()[0]})\n")
            print("| tool | median s | best s | peak RSS MB |")
            print("|---|---|---|---|")
            rows = [("portacheck (this tree)", os.path.join(os.path.dirname(HERE), "src"))]
            if args.prev_src:
                rows.append(("portacheck 0.3.0 @ round 2", args.prev_src))
            if args.old_src:
                rows.append(("portacheck 0.2.0", args.old_src))
            for name, src in rows:
                med, best, rss = time_scan(src, pf, args.runs)
                print(f"| {name} | {med:.2f} | {best:.2f} | {rss} |")
            a, b = time_precommit(paths, args.runs)
            print(f"| pre-commit regex (regex only, no Python start-up) | {a:.2f} | - | - |")
            print(f"| pre-commit case-conflict (set logic only) | {b:.2f} | - | - |")


if __name__ == "__main__":
    main()
