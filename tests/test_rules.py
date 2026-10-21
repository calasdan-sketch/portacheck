"""Name rules are pure functions — test them with names Windows would refuse to create."""
from portacheck.rules import check_component, check_relpath


def codes(findings):
    return [f.code for f in findings]


def test_reserved_names():
    assert codes(check_component("CON")) == ["reserved_name"]
    assert codes(check_component("con.txt")) == ["reserved_name"]
    assert codes(check_component("aux")) == ["reserved_name"]
    assert codes(check_component("COM1.log")) == ["reserved_name"]
    assert codes(check_component("lpt9")) == ["reserved_name"]
    # near misses are fine
    assert check_component("console.log") == []
    assert check_component("COM10.txt") == []
    assert check_component("AUXILIARY.md") == []


def test_invalid_characters():
    assert "invalid_char" in codes(check_component("a<b>.txt"))
    assert "invalid_char" in codes(check_component("what?.py"))
    assert "invalid_char" in codes(check_component("pipe|name"))
    assert "invalid_char" in codes(check_component("star*"))
    assert "invalid_char" in codes(check_component("quote\""))
    assert "invalid_char" in codes(check_component("tab\there"))  # control char
    assert check_component("perfectly-fine.py") == []


def test_trailing_dot_and_space():
    assert codes(check_component("report.")) == ["trailing_dot"]
    assert codes(check_component("report ")) == ["trailing_space"]
    assert check_component("report.txt") == []


def test_component_length():
    assert "component_too_long" in codes(check_component("x" * 300))


def test_multiple_problems_report_all():
    # "AUX." is the reserved device name AUX (Windows strips the trailing dot)
    # AND ends with a dot — both findings belong in the report
    found = codes(check_component("AUX."))
    assert "reserved_name" in found and "trailing_dot" in found
    # a space inside the stem is NOT stripped by Windows -> not reserved
    assert "reserved_name" not in codes(check_component("CON .txt"))


def test_relpath_checks_every_component():
    found = codes(check_relpath("src/aux/data<1>.csv"))
    assert found.count("reserved_name") == 1
    assert "invalid_char" in found
    # the path field points at the full relative path for context
    assert all(f.path == "src/aux/data<1>.csv" for f in check_relpath("src/aux/data<1>.csv"))
