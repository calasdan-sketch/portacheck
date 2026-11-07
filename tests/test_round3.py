"""Round 3: robustness (deep trees, huge paths, crashes), .gitmodules checks, look-alike names, settings file,
--rev, --explain, markdown output."""
import json
import os
import shutil
import subprocess
import sys
import time

import pytest

from portacheck import config as cfgmod
from portacheck import content, output, rules
from portacheck.baseline import dumps as bl_dumps, fingerprint
from portacheck.cli import main
from portacheck.rules import Finding, check_component
from portacheck.scan import GitError, git_snapshot, scan_paths, walk_entries

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


WINDOWS = sys.platform == "win32"


def run_stdin(monkeypatch, paths, args):
    """main() on a NUL-separated path list (so no hostile name is ever created on disk)."""
    import io

    class FakeStdin:
        buffer = io.BytesIO("\0".join(paths).encode("utf-8", "surrogateescape") + b"\0")

    monkeypatch.setattr(sys, "stdin", FakeStdin)
    return main(args + ["--stdin0"])


def add_index(cwd, path, blob=b"x\n"):
    """Put a path into the index without creating it on disk (works for names the OS cannot hold)."""
    sha = git(cwd, "hash-object", "-w", "--stdin", input=blob).strip().decode()
    git(cwd, "update-index", "--add", "--cacheinfo", f"100644,{sha},{path}")


def commit_files(tmp_path, files):
    git(tmp_path, "init", "-q")
    for name, data in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode())
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "c")
    return tmp_path


# --- robustness ----------------------------------------------------------------------------------------

@pytest.mark.skipif(WINDOWS, reason="a 1300-deep path exceeds MAX_PATH there")
def test_disk_walk_survives_a_very_deep_tree(tmp_path):
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        for _ in range(1300):  # deeper than Python's default recursion limit
            os.mkdir("d")
            os.chdir("d")
        open("leaf.txt", "w").close()
    finally:
        os.chdir(cwd)
    paths, _ = walk_entries(str(tmp_path))
    assert len(paths) == 1301
    assert paths[-1].endswith("/leaf.txt")


def test_unreadable_folder_is_reported_not_skipped(tmp_path, monkeypatch):
    (tmp_path / "ok").mkdir()
    (tmp_path / "locked").mkdir()
    real = os.scandir

    def scandir(p):
        if str(p).endswith("locked"):
            raise PermissionError("denied")
        return real(p)

    monkeypatch.setattr(os, "scandir", scandir)
    errors = []
    walk_entries(str(tmp_path), errors=errors)
    assert errors == ["locked"]
    assert main([str(tmp_path)]) == 2  # fail closed: an incomplete scan must not pass


def test_huge_path_is_linear_and_flagged():
    t = time.time()
    f = scan_paths(["a/" * 150000 + "x", "ok/CON.txt", "Docs/a", "docs/b"])
    assert time.time() - t < 5  # was quadratic memory (tens of GB) before
    assert ("path_length_posix", "error") in {(x.code, x.severity) for x in f}
    assert "reserved_name" in codes(f) and "case_collision" in codes(f)  # the rest of the tree is still checked


def test_huge_path_components_are_still_checked():
    f = scan_paths(["x/" * 3000 + "CON/y"])
    assert {"path_length_posix", "reserved_name"} <= set(codes(f))


def test_macos_path_max_warns_once_at_the_shallowest():
    deep = "/".join(["d" * 40] * 30) + "/f.txt"  # ~1240 bytes
    f = [x for x in scan_paths([deep]) if x.code == "path_length_posix"]
    assert len(f) == 1 and f[0].severity == "warn" and "inside it" in f[0].detail
    assert not [x for x in scan_paths(["/".join(["d" * 30] * 20) + "/f.txt"]) if x.code == "path_length_posix"]


def test_lone_surrogate_never_crashes_output():
    f = scan_paths(["bad\ud800name"])
    output.render_json(f, "r", 1).encode("utf-8")
    output.render_sarif(f, "x").encode("utf-8")
    bl_dumps(f)


def test_internal_error_exits_2_not_1(monkeypatch, tmp_path, capsys):
    (tmp_path / "a.txt").write_text("x")
    monkeypatch.setattr("portacheck.cli.scan_paths", lambda *a, **k: 1 / 0)
    assert main([str(tmp_path)]) == 2
    assert "failing closed" in capsys.readouterr().err


def test_python_dash_m_works():
    src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
    r = subprocess.run([sys.executable, "-m", "portacheck", "--stdin0"], input=b"docs/CON.md\0",
                       env=dict(os.environ, PYTHONPATH=src), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert r.returncode == 1 and b"reserved_name" in r.stdout


def test_stdin0_newline_list_gets_a_hint(monkeypatch, capsys):
    import io

    class FakeStdin:
        buffer = io.BytesIO(b"a.txt\nb.txt\n")

    monkeypatch.setattr(sys, "stdin", FakeStdin)
    main(["--stdin0"])
    assert "forget -z" in capsys.readouterr().err


def test_baseline_write_is_atomic(tmp_path):
    from portacheck.baseline import write_atomic
    p = tmp_path / "b.json"
    write_atomic(str(p), "{}\n")
    assert p.read_text() == "{}\n" and [x.name for x in tmp_path.iterdir()] == ["b.json"]
    with pytest.raises(OSError):
        write_atomic(str(tmp_path / "nope" / "b.json"), "x")


def test_fingerprint_unchanged_for_findings_without_ident():
    # a baseline written by the previous round must keep matching
    import hashlib
    f = Finding("error", "reserved_name", "CON.txt", "x")
    assert fingerprint(f) == hashlib.sha256(b"reserved_name\0CON.txt").hexdigest()[:24]
    g = Finding("error", "submodule_url", ".gitmodules", "x", ident="a\0url")
    assert fingerprint(g) != fingerprint(Finding("error", "submodule_url", ".gitmodules", "x"))


# --- names ----------------------------------------------------------------------------------------------

def test_component_bytes_linux_limit():
    cjk = "あ" * 100  # 100 UTF-16 units, 300 UTF-8 bytes
    f = check_component(cjk)
    assert codes(f) == ["component_bytes"] and f[0].severity == "warn"
    assert check_component("あ" * 85) == []  # 255 bytes
    assert "component_too_long" in codes(check_component("あ" * 300))  # the NTFS error wins, no double report
    assert "component_bytes" not in codes(check_component("あ" * 300))


def test_mixed_script_words():
    assert "mixed_script" in codes(check_component("pаypal.txt"))        # Cyrillic a in Latin word
    assert "mixed_script" in codes(check_component("Οfice.docx"))        # Greek Omicron
    assert not codes(check_component("Привет.txt"))  # all Cyrillic
    assert not codes(check_component("Καλάς-report.txt"))  # Greek + separate Latin word
    assert not codes(check_component("πR.txt"))                          # pi is not a Latin look-alike
    assert not codes(check_component("café.txt"))


def test_confusable_siblings():
    f = scan_paths(["docs/README.md", "docs/RЕADME.md"])
    assert codes(f) == ["confusable_name", "mixed_script"] and {x.severity for x in f} == {"warn"}
    assert "confusable_name" in codes(scan_paths(["a/file.txt", "a/ﬁle.txt"]))        # ligature
    assert "confusable_name" in codes(scan_paths(["a/abc.txt", "a/ａｂｃ.txt"]))  # full-width
    assert "confusable_name" not in codes(scan_paths(["a/readme.md", "b/RЕADME.md"]))  # different folders
    assert "confusable_name" not in codes(scan_paths(["a/café.txt", "a/cafe.txt"]))
    # already a Unicode/case collision: not reported twice
    assert "confusable_name" not in codes(scan_paths(["a/é.txt", "a/é.txt"]))


def test_os_junk():
    for n in (".DS_Store", "sub/Thumbs.db", "desktop.ini", "._resource"):
        assert "os_junk" in codes(scan_paths([n])), n
    assert not codes(scan_paths(["._", "thumbs.dbx", "my.DS_Store.txt"]))  # "._" alone and near-misses are fine


# --- .gitmodules ----------------------------------------------------------------------------------------

GM = {
    "name ..": ('[submodule "../evil"]\n\tpath = e\n\turl = https://x/y\n', {"gitmodulesName"}),
    "name a/../b": ('[submodule "a/../b"]\n\tpath = e\n\turl = https://x/y\n', {"gitmodulesName"}),
    "name backslash": ('[submodule "a\\\\..\\\\b"]\n\tpath = e\n\turl = https://x/y\n', {"gitmodulesName"}),
    "name a..b ok": ('[submodule "a..b"]\n\tpath = e\n\turl = https://x/y\n', set()),
    "name ok": ('[submodule "lib/x"]\n\tpath = lib/x\n\turl = https://x/y\n', set()),
    "url dash": ('[submodule "a"]\n\tpath = e\n\turl = -oProxyCommand=id\n', {"gitmodulesUrl"}),
    "url dash quoted": ('[submodule "a"]\n\tpath = e\n\turl = "-ouch"\n', {"gitmodulesUrl"}),
    "url rel newline": ('[submodule "a"]\n\tpath = e\n\turl = ./%0a\n', {"gitmodulesUrl"}),
    "url git newline": ('[submodule "a"]\n\tpath = e\n\turl = git://h/%0ax\n', {"gitmodulesUrl"}),
    "path dash": ('[submodule "a"]\n\tpath = -x\n\turl = https://x/y\n', {"gitmodulesPath"}),
    "update bang": ('[submodule "a"]\n\tpath = e\n\turl = https://x/y\n\tupdate = !id\n', {"gitmodulesUpdate"}),
    "update merge ok": ('[submodule "a"]\n\tpath = e\n\turl = https://x/y\n\tupdate = merge\n', set()),
    "legacy section": ('[submodule.A]\n\tpath = e\n\turl = -x\n', {"gitmodulesUrl"}),
    "comments ok": ('# hi\n[submodule "a"] ; c\n\tpath = e # c\n\turl = https://x/y ; c\n', set()),
    "unparsable": ('[submodule "a"\n path = e\n', {"gitmodulesParse"}),
}
# git fsck message -> portacheck code
FSCK_TO_CODE = {"gitmodulesName": "submodule_name", "gitmodulesUrl": "submodule_url",
                "gitmodulesPath": "submodule_path", "gitmodulesUpdate": "submodule_update",
                "gitmodulesParse": "submodule_config"}


@needs_git
@pytest.mark.parametrize("label", sorted(GM))
def test_gitmodules_matches_git_fsck(tmp_path, label):
    """Every verdict is compared with the real git on the same file (the oracle)."""
    text, _ = GM[label]
    r = commit_files(tmp_path, {".gitmodules": text})
    out = subprocess.run(["git", "-C", str(r), "fsck", "--strict"], env=ENV, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT).stdout.decode()
    git_codes = {FSCK_TO_CODE[m] for m in FSCK_TO_CODE if m + ":" in out}
    ours = {f.code for f in content.gitmodules_findings(text.encode()) if f.severity == "error" or
            f.code == "submodule_config"}
    assert ours == git_codes, (label, out)


def test_gitmodules_table_documents_expectations():
    # the same table, without git: pins what we report for each case
    for label, (text, expect) in GM.items():
        got = {FSCK_TO_CODE[m] for m in expect}
        ours = {f.code for f in content.gitmodules_findings(text.encode())}
        assert got <= ours, label
        if not expect:
            assert not ours, label


def test_gitmodules_extras():
    assert [f.severity for f in content.gitmodules_findings(b'[submodule "a"]\n path = e\n url = ext::sh -c id\n')] == ["warn"]
    big = content.gitmodules_findings(b"#" * (content.GITMODULES_MAX + 1))
    assert codes(big) == ["submodule_config"] and big[0].severity == "error"
    two = content.gitmodules_findings(b'[submodule "../a"]\n url = -x\n[submodule "../b"]\n url = -y\n')
    assert len({(f.code, f.ident) for f in two}) == 4  # distinct identities: one baseline entry cannot hide the others


@needs_git
def test_gitmodules_flows_through_git_rev_and_disk(tmp_path, capsys):
    r = commit_files(tmp_path, {".gitmodules": '[submodule "../x"]\n\tpath = e\n\turl = https://x/y\n', "a.txt": "x"})
    for mode in (["--git"], ["--rev", "HEAD"], []):
        assert main([str(r), *mode, "--format", "json"]) == 1
        assert "submodule_name" in capsys.readouterr().out, mode
    assert main([str(r), "--git", "--disable", "submodule_name"]) == 0


# --- git modes ------------------------------------------------------------------------------------------

@needs_git
def test_git_scans_the_whole_repo_from_a_subfolder(tmp_path, capsys):
    r = commit_files(tmp_path, {"sub/ok.txt": "x"})
    add_index(r, "Docs/a.md")
    add_index(r, "docs/b.md")
    capsys.readouterr()
    assert main([str(r / "sub"), "--git"]) == 1  # the Docs/docs clash is outside sub/
    assert "case_collision" in capsys.readouterr().out
    assert git_snapshot(str(r / "sub")).paths == ["Docs/a.md", "docs/b.md", "sub/ok.txt"]


@needs_git
def test_rev_scans_a_commit_without_checkout(tmp_path, capsys):
    r = commit_files(tmp_path, {"ok.txt": "x"})
    add_index(r, "CON.txt")
    tree = git(r, "write-tree").strip().decode()
    head = git(r, "rev-parse", "HEAD").strip().decode()
    bad = git(r, "commit-tree", tree, "-p", head, "-m", "bad").strip().decode()
    git(r, "branch", "feature", bad)       # never checked out: that is the point of --rev
    git(r, "reset", "-q", "--mixed", "HEAD")
    capsys.readouterr()
    assert main([str(r), "--rev", "feature"]) == 1
    assert "CON.txt" in capsys.readouterr().out
    assert main([str(r), "--rev", "HEAD"]) == 0
    assert main([str(r), "--rev", "no-such-branch"]) == 2
    with pytest.raises(GitError):
        git_snapshot(str(r), "-x")


@needs_git
@pytest.mark.skipif(WINDOWS, reason="creating symlinks needs privileges on Windows")
def test_rev_reads_symlink_targets(tmp_path):
    r = commit_files(tmp_path, {"a.txt": "x"})
    os.symlink("../../out", r / "lnk")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "l")
    snap = git_snapshot(str(r), "HEAD")
    assert snap.symlinks == {"lnk": "../../out"}


@needs_git
@pytest.mark.skipif(WINDOWS, reason="the hook is a POSIX shell command")
def test_hostile_fsmonitor_config_is_not_run(tmp_path):
    marker = tmp_path / "marker"
    (tmp_path / "repo").mkdir()
    r = commit_files(tmp_path / "repo", {"a.txt": "x"})
    git(r, "config", "core.fsmonitor", f"touch {marker}; echo")
    assert main([str(r), "--git"]) == 0
    assert not marker.exists()


# --- settings file --------------------------------------------------------------------------------------

def test_toml_subset_agrees_with_tomllib():
    text = ('# c\n[other]\nx = [1,\n 2]\n[tool.portacheck]\ndisable = ["symlink", \'os_junk\']  # why\n'
            'prefix_len = 39\nstrict = true\nignore = [\n  "tests/*",\n  "docs/a b/*",\n]\n[tool.after]\nz = 1\n')
    sub = cfgmod.parse_toml_subset(text, ("tool.portacheck",))
    assert sub == {"disable": ["symlink", "os_junk"], "prefix_len": 39, "strict": True, "ignore": ["tests/*", "docs/a b/*"]}
    if cfgmod._tomllib is not None:
        assert cfgmod._tomllib.loads(text)["tool"]["portacheck"] == sub
    with pytest.raises(cfgmod.ConfigError):
        cfgmod.parse_toml_subset("[portacheck]\nstrict = maybe\n", ("portacheck",))


def test_config_validation():
    for bad in ("[portacheck]\nbogus = 1\n", "[portacheck]\nstrict = 1\n", "[portacheck]\nprefix_len = -1\n",
                "[portacheck]\ndisable = 3\n"):
        with pytest.raises(cfgmod.ConfigError):
            cfgmod.parse(".portacheck.toml", bad, trusted=True)
    c = cfgmod.parse("pyproject.toml", "[tool.portacheck]\nprefix-len = 10\n", trusted=False)
    assert c.get("prefix_len") == 10


def test_settings_file_applies_and_cli_overrides(tmp_path, capsys):
    (tmp_path / "a.txt").write_text("x")
    (tmp_path / "Thumbs.db").write_text("x")
    (tmp_path / ".portacheck.toml").write_text('[portacheck]\nstrict = true\n')
    assert main([str(tmp_path)]) == 1                      # warning fails because the file says strict
    assert main([str(tmp_path), "--no-config"]) == 0
    (tmp_path / ".portacheck.toml").write_text('[portacheck]\nstrict = true\ndisable = ["os_junk"]\n')
    assert main([str(tmp_path)]) == 0
    capsys.readouterr()


def test_pyproject_table_is_found(tmp_path):
    (tmp_path / "Thumbs.db").write_text("x")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n[tool.portacheck]\ndisable = ["os_junk"]\nstrict = true\n')
    assert main([str(tmp_path)]) == 0


def test_found_settings_cannot_switch_off_attack_checks(tmp_path, capsys, monkeypatch):
    cfgfile = tmp_path / ".portacheck.toml"
    cfgfile.write_text('[portacheck]\ndisable = ["reserved_name"]\n')
    assert run_stdin(monkeypatch, ["CON.txt"], [str(tmp_path)]) == 2
    assert "may not disable" in capsys.readouterr().err
    cfgfile.write_text('[portacheck]\nignore = ["*"]\n')
    assert run_stdin(monkeypatch, ["CON.txt"], [str(tmp_path)]) == 1        # ignore applies to ordinary checks only
    assert "may not hide" in capsys.readouterr().err
    assert run_stdin(monkeypatch, ["CON.txt"], [str(tmp_path), "--config", str(cfgfile)]) == 0  # named: trusted
    assert run_stdin(monkeypatch, ["CON.txt"], [str(tmp_path), "--no-config", "--ignore", "CON.txt"]) == 0
    assert run_stdin(monkeypatch, ["Thumbs.db"], [str(tmp_path)]) == 0     # an ordinary warning is ignorable


def test_bad_settings_file_fails_closed(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    (tmp_path / ".portacheck.toml").write_text("[portacheck\n")
    assert main([str(tmp_path)]) == 2
    assert main([str(tmp_path), "--config", str(tmp_path / "missing.toml")]) == 2


def test_stale_ignore_pattern_is_reported(tmp_path, capsys):
    (tmp_path / "a.txt").write_text("x")
    assert main([str(tmp_path), "--ignore", "nothing/*"]) == 0
    assert "matched no finding" in capsys.readouterr().err


# --- explain / markdown / sarif -------------------------------------------------------------------------

def test_every_code_is_explained(capsys):
    assert set(output.RULES) == set(output.EXPLAIN)
    for code in output.RULES:
        assert main(["--explain", code]) == 0
        assert "Why:" in capsys.readouterr().out
    assert main(["--explain", "nope"]) == 2


def test_sarif_rules_carry_help():
    doc = json.loads(output.render_sarif([], "1"))
    rule = {r["id"]: r for r in doc["runs"][0]["tool"]["driver"]["rules"]}["reserved_name"]
    assert rule["help"]["text"] and rule["helpUri"].startswith("https://")


def test_markdown_escapes_hostile_names():
    f = scan_paths(["a|b`c<script>?.txt", "x/‮evil?"])
    md = output.render_markdown(f, 2, False)
    assert "‮" not in md and "<script>" not in md
    for line in md.splitlines():
        if line.startswith("| error") or line.startswith("| warn"):
            assert line.count("|") - line.count("\\|") == 5, line  # 4 columns: no cell was split by a path
    assert md.startswith("### portacheck: FAIL")


def test_text_output_summarises_by_code():
    out = output.render_text(scan_paths(["CON.txt", "a?.txt", "b?.txt"]), False)
    assert "by code: invalid_char 2, reserved_name 1" in out


def test_long_paths_are_clipped_in_text_but_not_json():
    f = scan_paths(["a/" * 3000 + "x"])
    assert max(len(line) for line in output.render_text(f, False).splitlines()) < 3500
    assert len(json.loads(output.render_json(f, "r", 1))["findings"][0]["path"]) > 5000


def test_new_codes_are_registered():
    for code in ("component_bytes", "path_length_posix", "confusable_name", "mixed_script", "os_junk",
                 "submodule_name", "submodule_url", "submodule_path", "submodule_update", "submodule_config"):
        assert code in output.RULES
    assert rules.is_os_junk(".DS_Store") and not rules.is_os_junk("._")


# --- pass B regressions ---------------------------------------------------------------------------------

def test_gitmodules_bom_cannot_hide_a_hazard():
    f = content.gitmodules_findings('\ufeff[submodule "../x"]\n url = https://h/x\n'.encode())
    assert "submodule_name" in codes(f)
    assert not content.gitmodules_findings(b'[submodule "a"]\n url = ht\ttp://x\n')  # a tab is not a hazard (git agrees)


def test_gitmodules_parser_never_crashes():
    import random
    rnd = random.Random(7)
    frag = ['[submodule "', '"]', "[", "]", "=", "\\", "\n", " ", "url", "path", "update", "!", "-", "..", "\r\n", '"', "#",
            ";", "\ufeff", "\x00", "\xff", "submodule", "a"]
    for _ in range(3000):
        data = "".join(rnd.choice(frag) for _ in range(rnd.randint(0, 25))).encode("utf-8", "surrogatepass")
        for f in content.gitmodules_findings(data):
            assert f.code.startswith("submodule_")


def test_found_settings_cannot_shrink_the_scan(tmp_path, capsys):
    (tmp_path / "a.txt").write_text("x")
    for body in ('skip = ["src"]', "allow_empty = true"):
        (tmp_path / ".portacheck.toml").write_text("[portacheck]\n" + body + "\n")
        assert main([str(tmp_path)]) == 2, body
        assert "may not set" in capsys.readouterr().err
    assert main([str(tmp_path), "--config", str(tmp_path / ".portacheck.toml")]) == 0  # trusted when named


def test_huge_path_findings_name_the_offending_component():
    rel = "x/" * 2100 + "CON/y.txt"
    f = [x for x in scan_paths([rel]) if x.code == "reserved_name"]
    assert len(f) == 1 and f[0].path == "x/" * 2100 + "CON"
    many = scan_paths(["CON/" * 3000 + "z"])
    assert len([x for x in many if x.code == "reserved_name"]) == 20  # capped: naming each would copy the path 3000 times


def test_gitmv_and_new_since_survive_a_huge_path():
    from portacheck.fix import render_gitmv
    from portacheck.scan import new_path_set
    rel = "a/" * 60000 + "CON.txt"
    t = time.time()
    out = render_gitmv([rel, "ok/x?"], scan_paths([rel, "ok/x?"]))
    assert "git mv -- ok/x? ok/x_" in out or "git mv -- 'ok/x?' ok/x_" in out
    assert new_path_set([rel, "ok/y"], [rel]) >= {rel}
    assert time.time() - t < 10


def test_component_bytes_counts_raw_bytes_once():
    raw = b"\xff" * 300
    name = raw.decode("utf-8", "surrogateescape")
    assert "component_bytes" not in codes(check_component(name)) and "component_too_long" in codes(check_component(name))
