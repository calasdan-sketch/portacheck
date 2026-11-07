"""Settings file: ``.portacheck.toml`` (table ``[portacheck]``) or ``pyproject.toml`` (``[tool.portacheck]``).

Trust model. A settings file that sits inside the repository being scanned is
controlled by whoever wrote that repository, including the author of a pull
request. So a file that was *found* in the scanned folder may not switch off
or hide the checks that guard against attacks (``PROTECTED``), and every key it
sets is a plain default that command-line flags override. A file named with
``--config`` is trusted as given (take it from the base branch, not the PR).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:  # Python 3.11+
    import tomllib as _tomllib  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - exercised through parse_toml_subset in the tests
    _tomllib = None  # type: ignore[assignment]

#: checks that guard against attacks rather than inconvenience: an auto-discovered file cannot disable or ignore them
PROTECTED = frozenset({
    "git_dir_alias", "git_meta_alias", "symlink_meta", "symlink_traversal", "reserved_name",
    "submodule_name", "submodule_url", "submodule_path", "submodule_update", "submodule_config",
    "invalid_encoding", "path_length_posix",
})

KEYS = {"disable": list, "ignore": list, "skip": list, "prefix_len": int, "max_path": int,
        "strict": bool, "allow_empty": bool}


class ConfigError(ValueError):
    """The settings file is unreadable or invalid (callers must fail closed)."""


@dataclass
class Config:
    path: str = ""
    trusted: bool = True
    values: Dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)


def _unquote(v: str) -> Any:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] == '"':
        body = v[1:-1]
        if "\\" in body.replace("\\\\", "").replace('\\"', ""):
            raise ConfigError(f"unsupported escape in string {v}")
        return body.replace('\\"', '"').replace("\\\\", "\\")
    if len(v) >= 2 and v[0] == v[-1] == "'":
        return v[1:-1]
    if v in ("true", "false"):
        return v == "true"
    if re.fullmatch(r"[0-9]+", v):
        return int(v)
    raise ConfigError(f"unsupported value {v!r}")


def _split_array(body: str) -> List[Any]:
    items, cur, quote = [], "", ""
    for c in body:
        if quote:
            cur += c
            if c == quote and not cur.endswith("\\" + quote):
                quote = ""
        elif c in "\"'":
            quote = c
            cur += c
        elif c == ",":
            if cur.strip():
                items.append(_unquote(cur))
            cur = ""
        else:
            cur += c
    if quote:
        raise ConfigError("unterminated string in array")
    if cur.strip():
        items.append(_unquote(cur))
    return items


def _strip_comment(line: str) -> str:
    quote = ""
    for i, c in enumerate(line):
        if quote:
            if c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
        elif c == "#":
            return line[:i]
    return line


def parse_toml_subset(text: str, tables: Tuple[str, ...]) -> Dict[str, Any]:
    """Keys of the first table in ``tables`` that is present, for Pythons without ``tomllib``.

    Understands exactly what portacheck needs: ``key = "str" | 'str' | 123 | true | false | ["a", "b"]``
    (arrays may span lines), comments, and table headers. Anything else inside the table is an error.
    """
    wanted = None
    out: Dict[str, Any] = {}
    in_table = False
    buf: Optional[Tuple[str, str]] = None
    for raw in text.splitlines():
        line = _strip_comment(raw).strip()
        if buf is not None:
            buf = (buf[0], buf[1] + " " + line)
            if "]" in line:
                key, body = buf
                out[key] = _split_array(body[body.index("[") + 1:body.rindex("]")])
                buf = None
            continue
        if not line:
            continue
        m = re.fullmatch(r"\[\s*([A-Za-z0-9_.-]+)\s*\]", line)
        if m or line.startswith("["):
            if wanted is not None and in_table:
                break
            name = m.group(1) if m else ""
            if wanted is None and name in tables:
                wanted, in_table = name, True
            else:
                in_table = False
            continue
        if not in_table:
            continue
        k, eq, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if not eq or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", k):
            raise ConfigError(f"cannot read line {raw.strip()!r}")
        if v.startswith("["):
            if "]" in v:
                out[k] = _split_array(v[1:v.rindex("]")])
            else:
                buf = (k, v)
        else:
            out[k] = _unquote(v)
    if buf is not None:
        raise ConfigError("unterminated array")
    return out


def _load_table(path: str, text: str) -> Dict[str, Any]:
    tables = ("tool.portacheck",) if os.path.basename(path) == "pyproject.toml" else ("portacheck",)
    if _tomllib is not None:
        try:
            doc = _tomllib.loads(text)
        except Exception as e:  # tomllib.TOMLDecodeError
            raise ConfigError(f"invalid TOML: {e}") from e
        node: Any = doc
        for part in tables[0].split("."):
            node = node.get(part) if isinstance(node, dict) else None
        return node if isinstance(node, dict) else {}
    return parse_toml_subset(text, tables)


def parse(path: str, text: str, trusted: bool) -> Config:
    raw = _load_table(path, text)
    cfg = Config(path=path, trusted=trusted)
    for k, v in raw.items():
        key = k.replace("-", "_")
        want = KEYS.get(key)
        if want is None:
            raise ConfigError(f"unknown setting {k!r} (known: {', '.join(sorted(KEYS))})")
        if want is int and (isinstance(v, bool) or not isinstance(v, int) or v < 0):
            raise ConfigError(f"{k} must be a non-negative integer")
        if want is bool and not isinstance(v, bool):
            raise ConfigError(f"{k} must be true or false")
        if want is list and not (isinstance(v, list) and all(isinstance(x, str) for x in v)):
            raise ConfigError(f"{k} must be a list of strings")
        cfg.values[key] = v
    return cfg


def load(path: str, trusted: bool) -> Config:
    try:
        with open(path, "rb") as fh:
            data = fh.read(1_000_001)
    except OSError as e:
        raise ConfigError(f"cannot read {path}: {e}") from e
    if len(data) > 1_000_000:
        raise ConfigError(f"{path} is larger than 1 MB")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ConfigError(f"{path} is not UTF-8") from e
    return parse(path, text, trusted)


def discover(folder: str) -> Optional[Config]:
    """``.portacheck.toml``, else ``pyproject.toml`` with a ``[tool.portacheck]`` table, in ``folder`` only.
    The result is untrusted (see the module docstring). Symlinks are not followed."""
    for name in (".portacheck.toml", "pyproject.toml"):
        p = os.path.join(folder, name)
        if os.path.islink(p) or not os.path.isfile(p):
            continue
        cfg = load(p, trusted=False)
        if cfg.values or name == ".portacheck.toml":
            return cfg
    return None


def check_trust(cfg: Config) -> None:
    """Raise ConfigError if an untrusted settings file tries to switch off a protected check."""
    if cfg.trusted:
        return
    for key in ("skip", "allow_empty"):  # both make a scan see less, so only a trusted file or a flag may set them
        if cfg.get(key):
            raise ConfigError(f"{cfg.path} is inside the scanned folder and may not set {key}; "
                              "pass it on the command line, or use --config to name a file you trust")
    bad = sorted(set(cfg.get("disable", [])) & PROTECTED)
    if bad:
        raise ConfigError(
            f"{cfg.path} is inside the scanned folder and may not disable {', '.join(bad)}; "
            "pass --disable on the command line, or use --config to name a file you trust")
