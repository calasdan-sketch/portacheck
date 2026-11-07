"""Round 4: what a stranger gets from the built package: metadata that agrees with itself, plain errors, Windows-ish
console behaviour (simulated on any OS), settings-file parity between Python versions."""
import codecs
import io
import os
import re
import shutil
import subprocess
import sys

import pytest

import portacheck
from portacheck import config as cfgmod
from portacheck import scan
from portacheck.cli import main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
           GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid",
           GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


# ---- metadata agrees with itself -------------------------------------------------------------------------------

def test_version_agrees_everywhere():
    m = re.search(r'^version = "([^"]+)"', read("pyproject.toml"), re.M)
    assert m and m.group(1) == portacheck.__version__
    first = re.search(r"^## (\d+\.\d+\.\d+)", read("CHANGELOG.md"), re.M)
    assert first and first.group(1) == portacheck.__version__
    assert f"rev: v{portacheck.__version__}" in read("README.md")


def test_package_ships_what_a_stranger_needs():
    assert os.path.isfile(os.path.join(ROOT, "src", "portacheck", "py.typed"))
    py = read("pyproject.toml")
    for needle in ('py.typed', '[project.urls]', 'requires-python = ">=3.9"', 'license = "MIT"', "Typing :: Typed"):
        assert needle in py
    assert "CHANGELOG.md" in read("MANIFEST.in") and ".pre-commit-hooks.yaml" in read("MANIFEST.in")
    # every declared Python 3.x classifier is >= the declared minimum
    for v in re.findall(r"Python :: (3\.\d+)\"", py):
        assert int(v.split(".")[1]) >= 9


def test_pyproject_declares_no_runtime_dependencies():
    assert not re.search(r"^dependencies\s*=", read("pyproject.toml"), re.M)


def test_no_personal_paths_in_package():
    for dirpath, _, names in os.walk(os.path.join(ROOT, "src")):
        for n in names:
            if n.endswith(".py"):
                text = open(os.path.join(dirpath, n), encoding="utf-8").read()
                assert not re.search(r"/home/\w+|/Users/\w+|C:\\\\Users\\\\\w+", text.replace("jane.doe", "")), n


# ---- settings file: the same answer on every Python ------------------------------------------------------------

@pytest.mark.parametrize("text", ["[portacheck\nstrict = true\n", "[portacheck]\nstrict = true\n[\n"])
def test_subset_parser_rejects_broken_table_header_like_tomllib(text):
    with pytest.raises(cfgmod.ConfigError):
        cfgmod.parse_toml_subset(text, ("portacheck",))


def test_subset_parser_still_skips_other_tables_and_arrays_of_tables():
    text = '[[tool.other]]\nname = "x"\n[project]\nclassifiers = [\n  "a",\n]\n[portacheck]\nstrict = true\n'
    assert cfgmod.parse_toml_subset(text, ("portacheck",)) == {"strict": True}


def test_settings_file_with_byte_order_mark(tmp_path):
    p = tmp_path / "s.toml"
    p.write_bytes(b"\xef\xbb\xbf[portacheck]\nstrict = true\n")
    assert cfgmod.load(str(p), trusted=True).values == {"strict": True}


def test_baseline_with_byte_order_mark(tmp_path, capsys):
    p = tmp_path / "b.json"
    p.write_bytes(b"\xef\xbb\xbf" + b'{"portacheck_baseline": 1, "fingerprints": []}')
    assert main(["--stdin0", "--baseline", str(p), "--allow-empty"]) in (0, 2)  # parsed, not "not a baseline"
    assert "not a portacheck baseline" not in capsys.readouterr().err


# ---- plain-English errors, never a traceback ---------------------------------------------------------------------

def run_cli(args, stdin=b""):
    return subprocess.run([sys.executable, "-m", "portacheck"] + args, input=stdin, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=dict(ENV, PYTHONPATH=os.path.join(ROOT, "src")), cwd=ROOT)


@pytest.mark.parametrize("args", [
    ["/definitely/not/here"], ["--max-path", "0"], ["--max-path", "1"], ["--prefix-len", "-1"], ["--baseline", "/nope.json", "--stdin0"],
    ["--config", "/nope.toml", "--stdin0"], ["--explain", "nonsense"], ["--disable", "nonsense", "--stdin0"],
    ["--write-baseline", "/nonexistent-dir/b.json", "--stdin0"], ["--format", "nope"],
])
def test_user_errors_exit_2_without_traceback(args):
    r = run_cli(args, b"a.txt\0")
    assert r.returncode == 2, (args, r.stderr)
    assert b"Traceback" not in r.stderr
    assert r.stderr.strip()


def test_missing_file_errors_say_what_happened_not_errno():
    r = run_cli(["--baseline", "/nope.json", "--stdin0"], b"a\0")
    assert b"Errno" not in r.stderr and b"No such file" in r.stderr


@needs_git
def test_unknown_revision_is_plain_english(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, env=ENV)
    (tmp_path / "a.txt").write_text("x")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True, env=ENV)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "i"], check=True, env=ENV)
    r = run_cli(["--rev", "no-such-branch", str(tmp_path)])
    assert r.returncode == 2 and b"cannot find revision 'no-such-branch'" in r.stderr and b"exit 1" not in r.stderr


def test_help_documents_exit_codes():
    out = run_cli(["--help"]).stdout.decode()
    assert "exit codes" in out and "0 clean" in out and "2 the scan could not be done" in out


# ---- Windows-shaped output, simulated ---------------------------------------------------------------------------

def _run_main_with_stdout(monkeypatch, args, stdin_paths, encoding, newline):
    raw = io.BytesIO()
    out = io.TextIOWrapper(raw, encoding=encoding, newline=newline, write_through=True)
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(stdin_paths)))
    code = main(args)
    out.flush()
    return code, raw.getvalue()


def test_stdout_never_gets_crlf_so_a_fix_script_stays_runnable(monkeypatch):
    code, data = _run_main_with_stdout(monkeypatch, ["--stdin0", "--format", "gitmv"], b"docs/CON.md\0", "utf-8", "\r\n")
    assert code == 1 and b"git mv" in data and b"\r" not in data


def test_old_console_encoding_does_not_crash_and_stays_readable(monkeypatch):
    code, data = _run_main_with_stdout(monkeypatch, ["--stdin0"], "docs/CON.md\0p\u0430ypal.js\0caf\u00e9/x\0".encode(), "cp437", "\n")
    text = data.decode("cp437")
    assert code == 1 and "FAIL" in text and "\u2014" not in text and "- FAIL" in text


def test_ascii_console_handler_escapes_unknown_characters():
    assert codecs.lookup_error("portacheck_console")
    assert "a\u2014b\u0416".encode("ascii", "portacheck_console") == b"a-b\\u0416"


def test_folder_loop_check_is_skipped_when_volume_reports_inode_zero(tmp_path, monkeypatch):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "x.txt").write_text("1")
    (tmp_path / "b" / "y.txt").write_text("1")
    real = os.stat

    class Zero:
        def __init__(self, st):
            self.st_dev, self.st_ino = st.st_dev, 0

    monkeypatch.setattr(scan.os, "stat", lambda p, *a, **k: Zero(real(p)))
    paths, _ = scan.walk_entries(str(tmp_path))
    assert {"a/x.txt", "b/y.txt"} <= set(paths)


def test_closed_pipe_exits_quietly():
    r = subprocess.run(f'"{sys.executable}" -m portacheck --stdin0 --format json < /dev/null | head -c 0',
                       shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       env=dict(ENV, PYTHONPATH=os.path.join(ROOT, "src")), cwd=ROOT) if os.name == "posix" else None
    if r is not None:
        assert b"Traceback" not in r.stderr


def test_subset_parser_rejects_duplicate_keys_like_tomllib():
    with pytest.raises(cfgmod.ConfigError):
        cfgmod.parse_toml_subset("[portacheck]\nstrict = true\nstrict = false\n", ("portacheck",))
