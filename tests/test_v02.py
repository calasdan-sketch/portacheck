"""0.2.0: correctness fixes, unicode checks, git/stdin sources, output formats, fail-closed CLI."""
import io
import json
import shutil
import subprocess
import sys

import pytest

from portacheck.cli import main
from portacheck.output import render_github, render_sarif, safe
from portacheck.rules import check_component, utf16_len, windows_fold
from portacheck.scan import (GitError, case_collisions, decode_nul_list, git_paths,
                             scan_paths, unicode_collisions, with_parents)

NFD_E = "e\u0301"  # e + combining acute
NFC_E = "\u00e9"


def codes(findings):
    return sorted(f.code for f in findings)


# --- rule fixes ----------------------------------------------------------

def test_backslash_is_invalid_on_windows():
    assert "invalid_char" in codes(check_component("a\\b.txt"))


def test_superscript_device_names_are_reserved():
    for n in ("COM\u00b9", "lpt\u00b2.txt", "Com\u00b3.log"):
        assert "reserved_name" in codes(check_component(n)), n
    assert check_component("COM4.txt") != []
    assert check_component("COM0.txt") == []  # not in Microsoft's list


def test_component_length_counts_utf16_units():
    emoji = "\U0001F600"
    assert utf16_len(emoji) == 2
    assert "component_too_long" in codes(check_component(emoji * 128))  # 256 units
    assert check_component(emoji * 127 + "a") == []  # 255 units


def test_windows_fold_does_not_equate_sharp_s():
    # str.casefold('straße') == 'strasse', but NTFS treats them as different names
    assert windows_fold("straße") != windows_fold("strasse")
    assert case_collisions(["straße", "strasse"]) == []
    assert case_collisions(["Straße", "straße"])
    assert case_collisions(["\u03a3igma", "\u03c3igma"])  # Greek capital vs small sigma


# --- unicode -------------------------------------------------------------

def test_invisible_and_bidi_chars_warn():
    f = check_component("invoice\u202egpj.exe")
    assert codes(f) == ["invisible_char"] and f[0].severity == "warn"
    assert "U+202E" in f[0].detail
    assert codes(check_component("zero\u200bwidth")) == ["invisible_char"]


def test_not_nfc_warns():
    assert codes(check_component("caf" + NFD_E)) == ["not_nfc"]
    assert check_component("caf" + NFC_E) == []


def test_unicode_collisions():
    found = unicode_collisions(["caf" + NFC_E, "caf" + NFD_E])
    assert len(found) == 1 and found[0].code == "unicode_collision"
    # normalization + case together
    assert unicode_collisions(["Caf" + NFC_E, "caf" + NFD_E])
    # pure case collisions are left to case_collisions (no double report)
    assert unicode_collisions(["A.txt", "a.txt"]) == []


# --- collisions dedupe + parents ----------------------------------------

def test_with_parents_and_dir_collision_reported_once():
    assert with_parents(["a/b/c.txt", "./a/d", "a//e/", "a/./e", "/", ""]) == ["a", "a/b", "a/b/c.txt", "a/d", "a/e"]
    found = scan_paths(["Src/a.py", "src/a.py", "src/b.py"])
    cc = [f for f in found if f.code == "case_collision"]
    assert len(cc) == 1 and cc[0].path == "Src"


# --- path length model ---------------------------------------------------

def test_path_length_uses_windows_prefix_and_reports_shallowest():
    deep = "/".join(["d" * 60] * 3) + "/" + "f" * 28  # folder 182, file 211 chars
    assert [f for f in scan_paths([deep], prefix_len=40) if f.code == "path_length"] == []
    found = [f for f in scan_paths([deep], prefix_len=50) if f.code == "path_length"]
    assert len(found) == 1 and found[0].path == deep
    # a directory that is already too long is reported once, with a count
    many = [("x" * 250) + f"/f{i}" for i in range(5)]
    found = [f for f in scan_paths(many, prefix_len=20) if f.code == "path_length"]
    assert len(found) == 1 and found[0].path == "x" * 250 and "+5" in found[0].detail


def test_exactly_max_path_warns():
    # MAX_PATH 260 includes the NUL, so a 260-char path does not fit
    rel = "a" * 210
    assert any(f.code == "path_length" for f in scan_paths([rel], max_path=260, prefix_len=50))
    assert not any(f.code == "path_length" for f in scan_paths([rel[:-1]], max_path=260, prefix_len=50))


# --- raw bytes / escaping -----------------------------------------------

def test_invalid_utf8_from_nul_list():
    paths = decode_nul_list(b"ok.txt\0bad\xff.txt\0\0")
    assert paths[0] == "ok.txt" and len(paths) == 2
    assert "invalid_encoding" in codes(check_component(paths[1]))


def test_safe_escapes_terminal_and_bidi_controls():
    nasty = "a\x1b[2Jb\u202ec\nd\\e" + "x\udcff"
    s = safe(nasty)
    assert "\x1b" not in s and "\u202e" not in s and "\n" not in s
    assert "\\u001b" in s and "\\u202e" in s and "\\x" + "ff" in s and "\\\\e" in s


def test_github_and_sarif_render_untrusted_paths_safely():
    findings = scan_paths(["bad:name,%x\nnext", "ok"])
    gh = render_github(findings)
    assert gh.count("\n") == len(findings) - 1  # one line per finding
    assert "file=bad%3Aname%2C%25x" in gh
    sarif = json.loads(render_sarif(findings, "0.0.0"))
    assert sarif["version"] == "2.1.0"
    res = sarif["runs"][0]["results"]
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in res}
    assert "bad%3Aname%2C%25x%0Anext" in uris
    ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in res} <= ids


# --- CLI -----------------------------------------------------------------

def test_cli_empty_dir_fails_closed(tmp_path, capsys):
    assert main([str(tmp_path)]) == 2
    assert "nothing to scan" in capsys.readouterr().err
    assert main([str(tmp_path), "--allow-empty"]) == 0


def test_cli_stdin0(monkeypatch, capsys):
    data = b"src/aux.py\0src/ok.py\0"
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data)))
    assert main(["--stdin0", "--format", "json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["scanned"] == 2 and out["errors"] == 1
    assert out["findings"][0]["path"] == "src/aux.py"


def test_cli_stdin0_empty_fails_closed(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"")))
    assert main(["--stdin0"]) == 2


def test_cli_ignore_glob(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"tests/fixtures/con.txt\0a.py\0")))
    assert main(["--stdin0", "--ignore", "tests/fixtures/*"]) == 0


def test_cli_text_output_is_escaped(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO("evil\x1b[31m\u202e.txt\0".encode())))
    assert main(["--stdin0"]) == 1
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\u202e" not in out


def test_cli_rejects_negative_numbers(capsys):
    with pytest.raises(SystemExit):
        main([".", "--prefix-len", "-1"])


# --- git index -----------------------------------------------------------

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                   cwd=cwd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@needs_git
def test_git_mode_reads_index_not_disk(tmp_path, capsys):
    _git(tmp_path, "init", "-q")
    (tmp_path / "tracked.txt").write_text("x", encoding="utf-8")
    (tmp_path / "untracked-aux").mkdir()
    (tmp_path / "untracked-aux" / "aux.py").write_text("x", encoding="utf-8")
    _git(tmp_path, "add", "tracked.txt")
    # a path that cannot exist on disk anywhere: inject it straight into the index
    blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=tmp_path, input=b"x",
                          stdout=subprocess.PIPE, check=True).stdout.decode().strip()
    _git(tmp_path, "update-index", "--add", "--cacheinfo", f"100644,{blob},docs/CON.md")
    assert sorted(git_paths(str(tmp_path))) == ["docs/CON.md", "tracked.txt"]
    assert main([str(tmp_path), "--git", "--format", "json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert [f["path"] for f in out["findings"]] == ["docs/CON.md"]  # untracked aux.py ignored


@needs_git
def test_git_mode_not_a_repo_fails_closed(tmp_path, capsys):
    (tmp_path / "a.txt").write_text("x", encoding="utf-8")
    with pytest.raises(GitError):
        git_paths(str(tmp_path / "nope-not-here"))
    assert main([str(tmp_path), "--git"]) == 2


def test_git_missing_binary(monkeypatch, tmp_path):
    def boom(*a, **k):
        raise FileNotFoundError("git")
    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(GitError):
        git_paths(str(tmp_path))


@pytest.mark.skipif(sys.platform in ("win32", "darwin"), reason="needs a filesystem that stores raw bytes")
def test_walk_with_undecodable_filename(tmp_path, capsys):
    import os
    try:
        with open(os.path.join(os.fsencode(tmp_path), b"bad\xff.txt"), "wb") as fh:
            fh.write(b"x")
    except OSError:
        pytest.skip("filesystem rejects non-UTF-8 names")
    assert main([str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "invalid_encoding" in out and "\\xff" in out
    assert main([str(tmp_path), "--format", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["findings"][0]["code"] == "invalid_encoding"
    assert main([str(tmp_path), "--format", "sarif"]) == 1
    assert json.loads(capsys.readouterr().out)["runs"][0]["results"]


# --- panel review fixes (0.2.0, round 2) --------------------------------

def test_reserved_names_match_git_for_windows():
    # compat/mingw.c is_valid_win32_path: spaces after the device name, then
    # end / '.' / ':' -> still the device; CONIN$/CONOUT$; LPT0 (isdigit)
    for n in ("CON .txt", "AUX  .tar.gz", "nul :stream", "PRN ", "CONIN$", "conout$.log",
              "LPT0", "lpt0.txt", "Com1 .x"):
        assert "reserved_name" in codes(check_component(n)), n
    for n in ("COM0", "CON X.txt", "CONINS", "CONIN", "CONOUT", "LPTX", "AUXILIARY", "NULL.md"):
        assert "reserved_name" not in codes(check_component(n)), n


def test_case_clash_inside_folder_not_hidden_by_parent_clash():
    found = case_collisions(with_parents(["Src/other", "src/Config", "src/config"]))
    paths = sorted(f.path for f in found)
    assert paths == ["Src", "src/Config"]
    # children under *different* clashing parents are not repeated
    found = case_collisions(with_parents(["Src/a.py", "src/a.py"]))
    assert [f.path for f in found] == ["Src"]


def test_folder_limit_is_248():
    # folder of 200 + 50 prefix = 250 >= 248 -> warn, though the file is < 260
    found = [f for f in scan_paths(["d" * 200 + "/f.txt"]) if f.code == "path_length"]
    assert len(found) == 1 and found[0].path == "d" * 200 and "limit 247" in found[0].detail
    assert not [f for f in scan_paths(["d" * 197 + "/f.txt"]) if f.code == "path_length"]
    # a leaf (file) of the same length is still under the 260 file limit
    assert not [f for f in scan_paths(["d" * 200]) if f.code == "path_length"]


def test_readme_prefix_example_length():
    assert len("C:\\Users\\jane.doe\\source\\repos\\project\\") == 39


def test_sarif_uri_and_json_are_byte_exact():
    import base64
    name = "bad\udcff\udcfe.txt"  # raw bytes ff fe
    findings = scan_paths([name])
    sarif = json.loads(render_sarif(findings, "0"))
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in sarif["runs"][0]["results"]}
    assert uris == {"bad%FF%FE.txt"}
    from portacheck.output import render_json
    data = json.loads(render_json(findings, ".", 1))
    assert base64.b64decode(data["findings"][0]["path_raw_b64"]) == b"bad\xff\xfe.txt"
    # a real backslash + "xff" is distinguishable from the raw byte
    other = json.loads(render_json(scan_paths(["bad\\xff\\xfe.txt"]), ".", 1))
    assert other["findings"][0]["path_raw_b64"] != data["findings"][0]["path_raw_b64"]


def test_dotdot_from_stdin_is_not_a_trailing_dot(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"../x/ok.py\0./y.py\0a/./b.py\0")))
    assert main(["--stdin0"]) == 0


def test_cjk_compatibility_ideographs_not_flagged():
    compat, unified = "\uf900", "\u8c48"  # NFC maps the first to the second
    assert check_component(compat + ".txt") == []
    assert unicode_collisions([compat + ".txt", unified + ".txt"]) == []
    # ordinary NFD is still caught next to a compat ideograph
    assert codes(check_component(compat + "caf" + NFD_E)) == ["not_nfc"]


def test_invalid_utf8_detail_matches_path_display():
    f = [x for x in check_component("bad\udcff") if x.code == "invalid_encoding"][0]
    assert "\\xff" in f.detail and "udcff" not in f.detail


def test_collision_details_escape_bidi_in_every_format():
    from portacheck.output import render_json
    evil = "a\u202eb.txt"
    findings = scan_paths([evil, "A\u202eB.txt"])
    cc = [f for f in findings if f.code == "case_collision"]
    assert cc and "\u202e" not in cc[0].detail and "\\u202e" in cc[0].detail
    sarif = json.loads(render_sarif(findings, "0"))
    assert all("\u202e" not in r["message"]["text"] for r in sarif["runs"][0]["results"])
    data = json.loads(render_json(findings, ".", 2))
    assert all("\u202e" not in f["detail"] for f in data["findings"])
    uc = unicode_collisions(["caf" + NFC_E + "\u202e", "caf" + NFD_E + "\u202e"])
    assert uc and "\u202e" not in uc[0].detail
