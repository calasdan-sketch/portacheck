#!/usr/bin/env python3
"""Mutation-style sanity check: break one condition at a time in a COPY of the source and confirm the tests fail.

    python benchmarks/mutation.py            # prints one line per mutation and a summary; exit 1 if any survives

Not a full mutation-testing tool: a hand-picked list of the conditions that decide a verdict. A "SURVIVED" line means
no test notices that change, i.e. a missing test.
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MUTATIONS = [
    ("rules.py", '"CON", "PRN", "AUX", "NUL", "CONIN$"', '"PRN", "AUX", "NUL", "CONIN$"'),
    ("rules.py", 'for i in range(0, 10)]', 'for i in range(1, 10)]'),
    ("rules.py", 'if low.startswith("git~1"):', 'if low.startswith("git~2"):'),
    ("rules.py", "if c not in \" .\":", "if c not in \".\":"),
    ("rules.py", "if c == \":\":\n            return True", "if c == \"::\":\n            return True"),
    ("rules.py", "return u if len(u) == 1 else c", "return u"),
    ("rules.py", "INVALID_CHARS = frozenset('<>:\"|?*\\\\')", "INVALID_CHARS = frozenset('<>\"|?*\\\\')"),
    ("rules.py", "if n16 > COMPONENT_MAX:", "if n16 > COMPONENT_MAX + 1:"),
    ("rules.py", "if nbytes > COMPONENT_MAX:", "if nbytes > COMPONENT_MAX + 1:"),
    ("rules.py", "elif name.endswith(\".\"):", "elif name.endswith(\"..\"):"),
    ("rules.py", 'if k == "git" and on_disk and name == ".git":', 'if k == "git" and name == ".git":'),
    ("rules.py", "return unicodedata.category(c) == \"Cf\"", "return unicodedata.category(c) == \"Cc\""),
    ("scan.py", 'r"(?:^|/)\\.{1,2}(?:/|$)|^/|//|/$"', 'r"(?:^|/)\\.{2}(?:/|$)|^/|//|/$"'),
    ("scan.py", "if inherited != clean:", "if False:"),
    ("scan.py", "k not in _REPO_ENV", "k not in ()"),
    ("cli.py", "if n < 2:", "if n < 0:"),
    ("cli.py", "return any(fnmatch.fnmatchcase(p, g) for g in args.only", "return any(not fnmatch.fnmatchcase(p, g) for g in args.only"),
    ("config.py", '"dotdot_component", "dot_component",', ""),
    ("output.py", '"partialFingerprints"', '"partialFingerprintz"'),
    ("baseline.py", "def fingerprint", "def fingerprint_unused"),
]


def main() -> int:
    survived = 0
    for fname, old, new in MUTATIONS:
        tmp = tempfile.mkdtemp(prefix="portacheck-mut-")
        try:
            shutil.copytree(os.path.join(ROOT, "src"), os.path.join(tmp, "src"),
                            ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
            shutil.copytree(os.path.join(ROOT, "tests"), os.path.join(tmp, "tests"),
                            ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copytree(os.path.join(ROOT, "benchmarks"), os.path.join(tmp, "benchmarks"),
                            ignore=shutil.ignore_patterns("__pycache__"))
            for extra in ("pyproject.toml", "README.md", "CHANGELOG.md", "LICENSE", "MANIFEST.in", ".pre-commit-hooks.yaml"):
                if os.path.exists(os.path.join(ROOT, extra)):
                    shutil.copy(os.path.join(ROOT, extra), tmp)
            target = os.path.join(tmp, "src", "portacheck", fname)
            with open(target, encoding="utf-8") as fh:
                text = fh.read()
            if text.count(old) != 1:
                print(f"BROKEN   {fname}: pattern found {text.count(old)} times: {old[:60]!r}")
                survived += 1
                continue
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(text.replace(old, new))
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
            env.pop("PYTHONPATH", None)
            r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "tests"], cwd=tmp,
                               env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
            if r.returncode == 0:
                print(f"SURVIVED {fname}: {old[:70]!r} -> {new[:40]!r}")
                survived += 1
            else:
                print(f"killed   {fname}: {old[:70]!r}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{len(MUTATIONS) - survived}/{len(MUTATIONS)} mutations caught")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
