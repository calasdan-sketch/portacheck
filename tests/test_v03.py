"""0.3.0: Git-metadata aliases, 8.3 short names, symlinks, fix script, baseline, --new-since, fast path."""
import json
import os
import random
import re
import shutil
import subprocess

import pytest

from portacheck import rules
from portacheck.baseline import BaselineError, apply as bl_apply, dumps as bl_dumps, loads as bl_loads
from portacheck.cli import main
from portacheck.fix import plan_renames, render_gitmv, sanitize_component, sh_quote
from portacheck.rules import check_component, dotgit_kind
from portacheck.scan import (git_added_paths, git_entries, new_path_set, scan_paths,
                             short_name_collisions, symlink_findings)

HAVE_GIT = shutil.which("git") is not None
needs_git = pytest.mark.skipif(not HAVE_GIT, reason="git not installed")
ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
           GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid",
           GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)


def codes(findings):
    return sorted({f.code for f in findings})


def git(cwd, *args, input=None):
    return subprocess.run(["git", "-C", str(cwd)] + list(args), input=input, env=ENV,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout


def repo(tmp_path):
    git(tmp_path, "init", "-q")
    return tmp_path


def add_index(cwd, path, mode="100644", blob=b"x\n"):
    """Force a path into the index, bypassing Git's own protections (what a hostile tree looks like)."""
    sha = git(cwd, "hash-object", "-w", "--stdin", input=blob).strip().decode()
    git(cwd, "-c", "core.protectNTFS=false", "-c", "core.protectHFS=false", "update-index", "--add",
        "--cacheinfo", f"{mode},{sha},{path}")


# --- Git-metadata aliases: cross-checked against real git -------------------------------------------

DOTGIT_NAMES = [
    ".git", ".GIT", ".Git", ".git ", ".git.", ".git . .", ".git...", "git~1", "GIT~1", "git~1.", "git~1 ",
    ".git::$INDEX_ALLOCATION", ".git:stream", "git~1:x", ".g\u200cit", ".\u200egit", ".gi\ufefft", ".GIT\u202e",
    "x\\.git\\y", "..git", ".gitx", "git", "git~2", ".gi", ".gitt", "legit", ".github", ".gitlab-ci.yml",
    ".gitignore", ".gitattributes", ".gitmodules", "git~", "gi~1",
]


def git_rejects(cwd, path):
    sha = git(cwd, "hash-object", "-w", "--stdin", input=b"x\n").strip().decode()
    r = subprocess.run(["git", "-C", str(cwd), "-c", "core.protectNTFS=true", "-c", "core.protectHFS=true",
                        "update-index", "--add", "--cacheinfo", f"100644,{sha},{path}"],
                       env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return r.returncode != 0


@needs_git
def test_git_dir_alias_matches_real_git(tmp_path):
    repo(tmp_path)
    for name in DOTGIT_NAMES:
        for path in (name + "/x", "sub/" + name + "/x"):
            expected = git_rejects(tmp_path, path) and name not in (".gitignore", ".gitattributes", ".gitmodules")
            got = any(f.code == "git_dir_alias" for f in scan_paths([path]))
            # '.gitmodules/x' etc. are rejected by git for another reason (directory named like a file); skip those
            if name.startswith(".git") and name[4:] in ("ignore", "attributes", "modules"):
                continue
            assert got == expected, (path, "git rejects" if expected else "git accepts")


@pytest.mark.parametrize("name,kind", [
    (".GitModules", "gitmodules"), (".gitmodules ", "gitmodules"), (".gitmodules.", "gitmodules"),
    ("GITMOD~1", "gitmodules"), ("gitmod~4", "gitmodules"), ("gi7eba~1", "gitmodules"),
    (".GITATTRIBUTES", "gitattributes"), ("gi7d29~2", "gitattributes"), (".gitignore::$DATA", "gitignore"),
    (".MAILMAP", "mailmap"), (".g\u200citmodules", "gitmodules"),
])
def test_meta_aliases(name, kind):
    assert dotgit_kind(name) == (kind, False)
    f = [x for x in check_component(name) if x.code == "git_meta_alias"]
    assert f and f[0].severity == ("error" if kind in ("gitmodules", "gitattributes") else "warn")


def test_canonical_meta_and_lookalikes_are_clean():
    for n in (".gitmodules", ".gitattributes", ".gitignore", ".mailmap", ".github", ".gitkeep", ".gitlab-ci.yml",
              "git", "gitmodules", "legit.py", "mailmap.txt", "gimp~1x"):
        assert not [f for f in check_component(n) if f.code in ("git_dir_alias", "git_meta_alias")], n


def test_exact_dotgit_ok_on_disk_walk_but_not_in_index():
    assert [f.code for f in check_component(".git", on_disk=True)] == []
    assert "git_dir_alias" in codes(check_component(".git"))
    assert "git_dir_alias" in codes(check_component(".git.", on_disk=True))  # an alias is never a real .git


# --- 8.3 short names ------------------------------------------------------------------------------

def test_short_name_collision():
    f = short_name_collisions(["d/longfilename.txt", "d/LONGFI~1.TXT"])
    assert [x.code for x in f] == ["short_name_collision"] and f[0].path == "d/longfilename.txt"
    assert f[0].paths == ("d/longfilename.txt", "d/LONGFI~1.TXT")
    assert short_name_collisions(["Program Files/a", "PROGRA~1/b"])  # folders too
    # no clash: different folder, different extension, 8.3-compliant name, or no tilde name present
    assert not short_name_collisions(["a/longfilename.txt", "b/LONGFI~1.TXT"])
    assert not short_name_collisions(["d/longfilename.txt", "d/LONGFI~1.PNG"])
    assert not short_name_collisions(["d/short.txt", "d/SHORT~1.TXT"])
    assert not short_name_collisions(["d/longfilename.txt", "d/longfile.txt"])


# --- symlinks ---------------------------------------------------------------------------------------

def test_symlink_findings():
    links = {"docs/ok": "../src/a", "bad": "../../outside", "abs": "/etc/passwd", "win": "C:\\x",
             "bs": "a\\b", ".gitmodules": "x", "GITMOD~1": "y"}
    f = symlink_findings(sorted(links) + ["docs/ok/inner.txt"], links)
    by = {(x.code, x.path) for x in f}
    assert ("symlink", "docs/ok") in by
    assert ("symlink_escape", "bad") in by and ("symlink_escape", "abs") in by and ("symlink_escape", "win") in by
    assert ("symlink_escape", "docs/ok") not in by  # stays inside the repo
    assert ("symlink_backslash", "bs") in by
    assert ("symlink_meta", ".gitmodules") in by and ("symlink_meta", "GITMOD~1") in by
    assert ("symlink_traversal", "docs/ok/inner.txt") in by
    assert all(x.severity == "error" for x in f if x.code in ("symlink_meta", "symlink_traversal"))


def test_symlink_without_target_is_still_flagged():
    assert codes(scan_paths(["l"], symlinks={"l": None})) == ["symlink"]


@needs_git
def test_git_entries_reads_symlinks_from_index(tmp_path):
    repo(tmp_path)
    add_index(tmp_path, "a/real.txt")
    add_index(tmp_path, "a/link", mode="120000", blob=b"../../outside")
    add_index(tmp_path, "b/\u00e9", mode="120000", blob=b"real.txt")
    paths, links = git_entries(str(tmp_path))
    assert sorted(paths) == ["a/link", "a/real.txt", "b/\u00e9"]
    assert links == {"a/link": "../../outside", "b/\u00e9": "real.txt"}
    f = scan_paths(paths, symlinks=links)
    assert ("symlink_escape", "a/link") in {(x.code, x.path) for x in f}


@needs_git
def test_symlink_below_symlink_in_real_index(tmp_path):
    repo(tmp_path)
    add_index(tmp_path, "lnk", mode="120000", blob=b"/tmp")
    # git refuses to put a path below a file in the index, so assert the pure rule on a tree listing instead
    paths, links = git_entries(str(tmp_path))
    assert "symlink_traversal" in codes(scan_paths(paths + ["lnk/inner"], symlinks=links))


# --- fast path equals the slow path --------------------------------------------------------------------

def test_fast_path_equals_slow_path(monkeypatch):
    rnd = random.Random(7)
    alphabet = list("abcAZ09 ._-~$:?*<>|\\\"+,;=[]()") + ["\u00e9", "e\u0301", "\u200c", "\U0001F600", "\t"]
    stems = ["CON", "con", "Nul", "COM1", "lpt9", "aux", "CONOUT$", "CONIN$", ".git", "git~1", "gi7eba~1",
             "gitmodules", ".gitmodules", "mailma~1", "LPT\u00b2", "COM0", "prn "]
    names = ["".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 12))) for _ in range(4000)]
    names += [s + e for s in stems for e in ("", ".txt", " .x", ".", " ", ":s", ".a.b")]
    fast = {n: [(f.severity, f.code, f.detail) for f in check_component(n)] for n in names}
    monkeypatch.setattr(rules, "_SAFE_ASCII", re.compile(r"(?!)"))
    for n in names:
        assert fast[n] == [(f.severity, f.code, f.detail) for f in check_component(n)], repr(n)


# --- fix script ----------------------------------------------------------------------------------------

def test_sanitize_component():
    assert sanitize_component("CON.txt") == "CON_.txt"
    assert sanitize_component("CON .tar.gz") == "CON_.tar.gz"
    assert sanitize_component("a?b:c*.txt") == "a_b_c_.txt"
    assert sanitize_component("report. . ") == "report"
    assert sanitize_component("in\u202evoice.txt") == "invoice.txt"
    assert sanitize_component("cafe\u0301.png") == "caf\u00e9.png"
    assert sanitize_component("...") == "_"
    assert len(sanitize_component("x" * 400 + ".txt").encode()) <= 255 and sanitize_component("x" * 400 + ".txt").endswith(".txt")


def test_plan_renames_deepest_first_and_unique():
    paths = ["CON/aux.txt", "CON/aux_.txt", "docs/a.txt", "docs/A.txt"]
    ren, manual = plan_renames(paths, scan_paths(paths))
    d = dict(ren)
    assert d["CON/aux.txt"] == "CON/aux__2.txt"  # aux_.txt is taken
    olds = [o for o, _ in ren]
    assert olds.index("CON/aux.txt") < olds.index("CON")  # child before parent
    newp = [n for _, n in ren]
    assert len(newp) == len(set(newp))
    assert d["docs/a.txt"] == "docs/a_2.txt" and "docs/A.txt" not in d  # first spelling stays


def test_never_suggests_renaming_into_a_git_alias():
    paths = [".git ./hooks/x", "ok"]
    ren, manual = plan_renames(paths, scan_paths(paths))
    assert ren == [] and any("by hand" in m for m in manual)


def test_sh_quote_is_display_safe():
    assert sh_quote("plain/name-1.txt") == "plain/name-1.txt"
    assert sh_quote("a b") == "'a b'"
    q = sh_quote("in\u202evoice\n$(touch x)")
    assert q.startswith("$'") and "\u202e" not in q and "\n" not in q and "\\u202e" in q
    assert sh_quote("bad\udcffbyte") == "$'bad\\xffbyte'"


@needs_git
@pytest.mark.skipif(shutil.which("bash") is None or os.name == "nt", reason="needs POSIX bash")
def test_fix_script_end_to_end_makes_repo_clean(tmp_path):
    repo(tmp_path)
    bad = ["CON/notes.txt", "docs/Readme.md", "docs/README.md", "build/report.", "x/a?b.txt",
           "caf\u00e9.png", "cafe\u0301.png", "longfilename.txt", "LONGFI~1.TXT", "in\u202evoice.txt", "ok/fine.txt"]
    for p in bad:
        add_index(tmp_path, p)
        f = tmp_path / p
        try:
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(b"x\n")
        except OSError:
            pass
    paths, links = git_entries(str(tmp_path))
    findings = scan_paths(paths, symlinks=links)
    assert findings
    script = render_gitmv(paths, findings)
    assert "git mv --" in script and "ok/fine.txt" not in script
    (tmp_path / "fix.sh").write_text(script, encoding="utf-8")
    env = dict(ENV, LC_ALL="C.UTF-8")
    r = subprocess.run(["bash", "fix.sh"], cwd=tmp_path, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert r.returncode == 0, r.stderr.decode()
    after = scan_paths(git_entries(str(tmp_path))[0])
    assert [x for x in after if x.severity == "error"] == [], [(x.code, x.path) for x in after]


# --- baseline ---------------------------------------------------------------------------------------------

def test_baseline_roundtrip_and_stale():
    old = scan_paths(["CON.txt", "a?.txt"])
    base = bl_loads(bl_dumps(old))
    new, hidden, stale = bl_apply(scan_paths(["CON.txt", "a?.txt", "NUL"]), base)
    assert [f.path for f in new] == ["NUL"] and hidden == 2 and stale == 0
    new, hidden, stale = bl_apply(scan_paths(["CON.txt"]), base)
    assert new == [] and hidden == 1 and stale == 1


@pytest.mark.parametrize("text", ["", "[]", "{}", '{"portacheck_baseline": 2, "fingerprints": []}',
                                  '{"portacheck_baseline": 1, "fingerprints": [1]}', "not json"])
def test_bad_baseline_fails_closed(text, tmp_path, capsys):
    with pytest.raises(BaselineError):
        bl_loads(text)
    f = tmp_path / "b.json"
    f.write_text(text)
    (tmp_path / "x").mkdir()
    assert main([str(tmp_path / "x"), "--allow-empty", "--baseline", str(f)]) == 2
    assert main([str(tmp_path / "x"), "--allow-empty", "--baseline", str(tmp_path / "missing.json")]) == 2


def test_cli_baseline_workflow(tmp_path, capsys, monkeypatch):
    import io
    import sys
    data = b"CON.txt\0ok.txt\0"
    base = tmp_path / "base.json"
    monkeypatch.setattr(sys, "stdin", type("S", (), {"buffer": io.BytesIO(data)})())
    assert main(["--stdin0", "--write-baseline", str(base)]) == 0
    monkeypatch.setattr(sys, "stdin", type("S", (), {"buffer": io.BytesIO(data)})())
    assert main(["--stdin0", "--baseline", str(base)]) == 0  # existing debt hidden
    monkeypatch.setattr(sys, "stdin", type("S", (), {"buffer": io.BytesIO(data + b"NUL\0")})())
    assert main(["--stdin0", "--baseline", str(base)]) == 1  # new debt fails


# --- --new-since -------------------------------------------------------------------------------------------

@needs_git
def test_new_since_reports_only_new_paths_but_sees_old_collisions(tmp_path, capsys):
    repo(tmp_path)
    for p in ("CON.txt", "keep/README.md", "legacy/old?.txt"):
        add_index(tmp_path, p)
    git(tmp_path, "commit", "-q", "-m", "base", "--no-verify")
    add_index(tmp_path, "keep/readme.md")   # new file colliding with an OLD one
    add_index(tmp_path, "new/AUX.log")      # new + bad
    add_index(tmp_path, "PRN/ok.txt")       # new folder with a bad name
    paths, _ = git_entries(str(tmp_path))
    added = git_added_paths(str(tmp_path), "HEAD")
    assert sorted(added) == ["PRN/ok.txt", "keep/readme.md", "new/AUX.log"]
    assert {"PRN", "new"} <= new_path_set(paths, added) and "keep" not in new_path_set(paths, added)
    capsys.readouterr()
    rc = main(["--git", str(tmp_path), "--new-since", "HEAD", "--format", "json"])
    out = json.loads(capsys.readouterr().out)
    got = {(f["code"], f["path"]) for f in out["findings"]}
    assert rc == 1
    assert ("reserved_name", "new/AUX.log") in got and ("reserved_name", "PRN") in got
    assert any(c == "case_collision" for c, _ in got)
    assert not any(p in ("CON.txt", "legacy/old?.txt") for _, p in got)  # old debt not blamed on this change


@needs_git
def test_new_since_bad_ref_and_missing_git_flag(tmp_path, capsys):
    repo(tmp_path)
    add_index(tmp_path, "a.txt")
    assert main(["--git", str(tmp_path), "--new-since", "no-such-ref"]) == 2
    assert main(["--git", str(tmp_path), "--new-since=--output=x"]) == 2  # option-looking ref refused
    assert main([str(tmp_path), "--new-since", "HEAD"]) == 2


# --- CLI niceties --------------------------------------------------------------------------------------------

def test_disable_and_list_codes(capsys, monkeypatch):
    import io
    import sys
    assert main(["--list-codes"]) == 0
    assert "short_name_collision" in capsys.readouterr().out
    monkeypatch.setattr(sys, "stdin", type("S", (), {"buffer": io.BytesIO(b"CON.txt\0")})())
    assert main(["--stdin0", "--disable", "reserved_name"]) == 0
    assert main(["--stdin0", "--disable", "nonsense"]) == 2


# --- benchmark gates -----------------------------------------------------------------------------------------

def _bench():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "pc_bench", os.path.join(os.path.dirname(__file__), "..", "benchmarks", "bench.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_benchmark_corpus_gate():
    """The committed accuracy numbers must not regress: no false positives, every hostile case caught."""
    b = _bench()
    from portacheck import scan
    rnd = random.Random(20261107)
    cases = b.hostile_cases(rnd) + b.benign_cases(rnd, 500)
    r = b.score(b.portacheck_detector(scan), cases)
    assert r["fp"] == 0, r
    assert r["fn"] == 0, {k: v for k, v in r["per"].items() if v[0] != v[1]}


@needs_git
def test_git_parity_fuzz_matches_real_git():
    b = _bench()
    from portacheck import scan
    tp, fp, fn, tn = b.git_parity(400, 3, scan)
    assert (fp, fn) == (0, 0) and tp > 20


def test_empty_component_does_not_crash():
    assert check_component("") == []


def test_sarif_has_stable_fingerprints_and_related_locations():
    from portacheck.output import render_sarif
    doc = json.loads(render_sarif(scan_paths(["a/X.txt", "a/x.txt"]), "t"))
    res = [r for r in doc["runs"][0]["results"] if r["ruleId"] == "case_collision"][0]
    assert len(res["partialFingerprints"]["portacheck/v1"]) == 24
    assert res["relatedLocations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "a/x.txt"
