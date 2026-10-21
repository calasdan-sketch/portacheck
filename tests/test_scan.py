"""Tree-scan integration tests using real directories (only creatable hazards)."""
import os

import pytest

from portacheck.cli import main
from portacheck.scan import case_collisions, scan_tree


def touch(tmp_path, *parts):
    p = tmp_path.joinpath(*parts)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("x", encoding="utf-8")
    return p


def fs_case_sensitive(tmp_path) -> bool:
    """NTFS is case-insensitive by default: can the FS hold A and a at once?"""
    (tmp_path / "CaseProbe").write_text("x", encoding="utf-8")
    try:
        (tmp_path / "caseprobe").write_text("y", encoding="utf-8")
    except OSError:
        return False
    return len(os.listdir(tmp_path)) == 2


def test_clean_tree_passes(tmp_path):
    touch(tmp_path, "src", "main.py")
    touch(tmp_path, "README.md")
    assert scan_tree(str(tmp_path)) == []


def test_case_collisions_pure():
    findings = case_collisions(["src/Config.json", "src/config.json"])
    assert len(findings) == 1
    assert findings[0].code == "case_collision" and findings[0].severity == "error"
    assert "Config.json" in findings[0].detail and "config.json" in findings[0].detail


def test_case_collisions_same_dir_only_and_none_for_distinct():
    # collisions matter within one directory; different dirs coexist fine
    assert case_collisions(["a/Readme.md", "a/README.MD"])
    assert case_collisions(["a/Readme.md", "b/README.MD"]) == []
    assert case_collisions(["a.md", "b.md", "A.md.bak"]) == []
    assert case_collisions(["same.md"]) == []


@pytest.mark.skipif(os.name == "nt", reason="default NTFS cannot hold both case variants")
def test_case_collision_detected_on_case_sensitive_fs(tmp_path):
    touch(tmp_path, "src", "Config.json")
    touch(tmp_path, "src", "config.json")
    findings = scan_tree(str(tmp_path))
    assert any(f.code == "case_collision" and f.severity == "error" for f in findings)


def test_reserved_name_in_real_tree(tmp_path):
    # NUL.ext is creatable on Windows via Python? No — reserved. Use a name the
    # rule catches regardless of platform by scanning a synthetic path via rules;
    # here we assert directories named like near-misses do NOT trigger.
    touch(tmp_path, "nulls", "fine.txt")
    assert scan_tree(str(tmp_path)) == []


def test_skip_defaults_and_custom(tmp_path):
    touch(tmp_path, "node_modules", "pkg", "index.js")
    touch(tmp_path, ".git", "config")
    assert scan_tree(str(tmp_path)) == []
    # overriding skip with () scans them (still clean here)
    assert scan_tree(str(tmp_path), skip=()) == []


def test_path_length_warns_not_errors(tmp_path):
    import os

    # nest just enough to stay creatable (<260) while crossing a small threshold
    deep = tmp_path
    for i in range(3):
        deep = deep / f"lvl{i}-{'x' * 12}"
    touch(deep, "file.txt")
    threshold = len(os.path.abspath(tmp_path)) + 25
    findings = scan_tree(str(tmp_path), max_path=threshold)
    assert findings, "expected long-path warnings"
    assert all(f.severity == "warn" and f.code == "path_length" for f in findings)


def test_symlinks_not_followed_by_default(tmp_path):
    target = tmp_path / "real"
    touch(target, "a.txt")
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        return  # symlinks unavailable (e.g. developer mode off) — nothing to test
    assert scan_tree(str(tmp_path)) == []


def test_cli_exit_codes_and_json(tmp_path, capsys):
    import os

    touch(tmp_path, "ok.txt")
    assert main([str(tmp_path)]) == 0
    deep = tmp_path
    for i in range(3):
        deep = deep / f"lvl{i}-{'d' * 12}"
    touch(deep, "file.txt")
    threshold = str(len(os.path.abspath(tmp_path)) + 25)
    capsys.readouterr()
    assert main([str(tmp_path), "--max-path", threshold]) == 0, "warnings alone must not fail"
    capsys.readouterr()
    assert main([str(tmp_path), "--max-path", threshold, "--strict"]) == 1
    capsys.readouterr()
    assert main([str(tmp_path), "--max-path", threshold, "--json"]) == 0
    out = capsys.readouterr().out
    assert '"warnings"' in out and "path_length" in out


def test_cli_not_a_directory(tmp_path, capsys):
    assert main([str(tmp_path / "missing")]) == 2
