"""Round 5: the author line, git-source dot components, wrong-repository environment, --only, golden files for every
output format, and seeded property tests (no third-party package needed; hypothesis is used when installed)."""
import io
import os
import random
import re
import shutil
import subprocess
import sys
import unicodedata

import pytest

import portacheck
from portacheck import scan_paths
from portacheck.cli import main
from portacheck.fix import render_gitmv
from portacheck.output import render_github, render_json, render_markdown, render_sarif, render_text
from portacheck.rules import windows_fold
from portacheck.scan import GitError, check_git_env

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLDEN = os.path.join(ROOT, "tests", "golden")
AUTHOR = "Calas Automations Inc."
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
           GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid",
           GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def git(cwd, *args, inp=None):
    return subprocess.run(["git", "-C", str(cwd)] + list(args), env=ENV, input=inp, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()


# ---- author line -----------------------------------------------------------------------------------------------

def test_author_is_pinned_everywhere(capsys):
    py = read("pyproject.toml")
    assert f'authors = [{{ name = "{AUTHOR}" }}]' in py
    assert f'maintainers = [{{ name = "{AUTHOR}" }}]' in py
    assert f"Copyright (c) 2026 {AUTHOR}" in read("LICENSE")
    assert portacheck.__author__ == AUTHOR
    with pytest.raises(SystemExit):
        main(["--version"])
    out = capsys.readouterr().out
    assert AUTHOR in out and portacheck.__version__ in out
    assert f'"organization": "{AUTHOR}"' in render_sarif([], "1")


def test_old_handle_is_not_used_as_an_author_label():
    for dirpath, dirs, names in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in (".git", ".venv", ".pytest_cache", ".ruff_cache", "__pycache__",
                                                "build", "dist") and not d.endswith(".egg-info")]
        for n in names:
            if n.endswith((".py", ".md", ".toml", ".yml", ".yaml", ".in")) or n == "LICENSE":
                text = open(os.path.join(dirpath, n), encoding="utf-8").read()
                # real GitHub addresses may keep the account name; nothing else may
                rest = re.sub(r"https://github\.com/calasdan-sketch/[\w.-]+", "", text)
                assert "calasdan-sketch" not in rest or n == "test_round5.py", os.path.join(dirpath, n)


# ---- git-source dot components ---------------------------------------------------------------------------------

def test_dot_components_only_for_git_sources():
    assert not scan_paths(["../x/ok.py", "./y.py", "a/./b.py"])  # a file list from `find`: ordinary relative paths
    f = scan_paths(["a/../b", "c/./d", "e//f", "ok.txt"], strict_dots=True)
    assert sorted((x.code, x.path) for x in f) == [("dot_component", "c/./d"), ("dot_component", "e//f"),
                                                    ("dotdot_component", "a/../b")]
    assert not scan_paths([".gitignore", "a/.hidden", "a/..b", "a/b"], strict_dots=True)


@needs_git
def test_dotdot_entry_in_a_real_git_tree(tmp_path, capsys):
    git(tmp_path, "init", "-q")
    blob = git(tmp_path, "hash-object", "-w", "--stdin", inp=b"x")
    tree = git(tmp_path, "mktree", inp=f"100644 blob {blob}\t..\n100644 blob {blob}\tok\n".encode())
    commit = git(tmp_path, "commit-tree", tree, "-m", "x")
    git(tmp_path, "update-ref", "refs/heads/evil", commit)
    assert main(["--rev", "evil", str(tmp_path)]) == 1
    assert "dotdot_component" in capsys.readouterr().out
    # an auto-found settings file may not disable it
    from portacheck import config
    assert {"dotdot_component", "dot_component"} <= config.PROTECTED


# ---- wrong repository from the environment ---------------------------------------------------------------------

@needs_git
def test_inherited_git_dir_for_another_repository_fails_closed(tmp_path, monkeypatch, capsys):
    a, b = tmp_path / "a", tmp_path / "b"
    for d in (a, b):
        d.mkdir()
        git(d, "init", "-q")
    (b / "CON.txt").write_text("x")
    git(b, "add", "-A")
    monkeypatch.setenv("GIT_DIR", str(a / ".git"))
    with pytest.raises(GitError):
        check_git_env(str(b))
    assert main(["--git", str(b)]) == 2  # used to scan repository a and PASS
    assert "different repository" in capsys.readouterr().err
    monkeypatch.setenv("GIT_DIR", str(b / ".git"))  # the repository we were asked about: fine
    check_git_env(str(b))
    assert main(["--git", str(b)]) == 1


# ---- --only ----------------------------------------------------------------------------------------------------

def test_only_limits_the_report_to_one_folder(monkeypatch, capsys):
    data = b"pkg/a/CON\0pkg/b/x\0pkg/b/X\0"

    def run(*extra):
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data)))
        rc = main(["--stdin0", "--format", "json"] + list(extra))
        return rc, capsys.readouterr().out
    rc, out = run("--only", "pkg/a/*")
    assert rc == 1 and "reserved_name" in out and "case_collision" not in out
    rc, out = run("--only", "pkg/b/*")
    assert "case_collision" in out and "reserved_name" not in out
    rc, out = run("--only", "pkg/zzz/*")
    assert rc == 0


# ---- golden files: every output format -------------------------------------------------------------------------

GOLDEN_PATHS = ["docs/CON.md", "src/Util.py", "src/util.py", "café.txt", "café.txt", "a‮b.txt",
                "bad:name", "trail.", ".GITMODULES", "ok/fine.txt", "gone/\x07bell"]


def render_all():
    fs = scan_paths(GOLDEN_PATHS)
    return {
        "text.txt": render_text(fs, False), "json.json": render_json(fs, "<golden>", len(GOLDEN_PATHS)),
        "sarif.json": render_sarif(fs, "0.0.0"), "markdown.md": render_markdown(fs, len(GOLDEN_PATHS), False),
        "github.txt": render_github(fs), "gitmv.sh": render_gitmv(GOLDEN_PATHS, fs),
    }


@pytest.mark.parametrize("name", sorted(render_all()))
def test_golden_output(name):
    got = render_all()[name]
    path = os.path.join(GOLDEN, name)
    if os.environ.get("PORTACHECK_UPDATE_GOLDEN"):
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(got + "\n")
    with open(path, encoding="utf-8", newline="") as fh:
        want = fh.read()
    assert got + "\n" == want, f"{name} changed; if on purpose, rerun with PORTACHECK_UPDATE_GOLDEN=1"


# ---- seeded property tests -------------------------------------------------------------------------------------

TOKENS = list("aAbBcC.x ") + ["é", "é", "É", "‮", "\x07", "ß", "SS", "ı", "I", "i", "\\",
                              ":", "~1", "con", "CON"]


def rand_paths(rng):
    def comp():
        return "".join(rng.choice(TOKENS) for _ in range(rng.randint(1, 5)))
    return ["/".join(comp() for _ in range(rng.randint(1, 3))) for _ in range(rng.randint(1, 8))]


def key(f):
    return (f.severity, f.code, f.path, f.detail, f.paths)


def test_property_order_and_duplicates_do_not_matter():
    rng = random.Random(20261108)
    for _ in range(600):
        ps = rand_paths(rng)
        base = sorted(map(key, scan_paths(ps)))
        shuffled = ps[:]
        rng.shuffle(shuffled)
        assert base == sorted(map(key, scan_paths(shuffled))), ps
        assert base == sorted(map(key, scan_paths(ps + ps))), ps


def test_property_case_collision_matches_brute_force():
    rng = random.Random(7)
    for _ in range(600):
        ps = rand_paths(rng)
        every, seen, expect = set(), {}, False
        for p in ps:
            parts = p.split("/")
            every.update("/".join(parts[:i]) for i in range(1, len(parts) + 1))
        for p in sorted(every):
            k = windows_fold(p)
            expect = expect or (k in seen and seen[k] != p)
            seen.setdefault(k, p)
        assert expect == any(f.code == "case_collision" for f in scan_paths(ps)), ps


def test_property_no_output_format_carries_raw_control_or_bidi_characters():
    rng = random.Random(99)
    bad = ("Cc", "Cf", "Zl", "Zp", "Cs")
    for _ in range(300):
        ps = rand_paths(rng)
        fs = scan_paths(ps)
        for out in (render_text(fs, False), render_markdown(fs, len(ps), False), render_github(fs),
                    render_sarif(fs, "1"), render_json(fs, "r", len(ps)), render_gitmv(ps, fs)):
            for line in out.split("\n"):
                for c in line:
                    assert unicodedata.category(c) not in bad and c != "\r", (repr(c), ps)


def test_hypothesis_when_installed():
    hyp = pytest.importorskip("hypothesis")
    st = pytest.importorskip("hypothesis.strategies")
    tok = st.sampled_from(TOKENS)
    comp = st.lists(tok, min_size=1, max_size=5).map("".join)
    paths = st.lists(st.lists(comp, min_size=1, max_size=3).map("/".join), min_size=1, max_size=8)

    @hyp.settings(max_examples=300, deadline=None)
    @hyp.given(paths)
    def check(ps):
        assert sorted(map(key, scan_paths(ps))) == sorted(map(key, scan_paths(list(reversed(ps)))))
    check()


def test_byte_limit_boundary_is_exact():
    from portacheck.rules import check_component
    ok = "é" * 127 + "a"      # 255 UTF-8 bytes
    over = "é" * 127 + "ab"   # 256 UTF-8 bytes
    assert not [f for f in check_component(ok) if f.code == "component_bytes"]
    assert [f.code for f in check_component(over) if f.code == "component_bytes"] == ["component_bytes"]
