# portacheck

**Catch file names that break Windows and macOS checkouts, in CI on Linux, before a teammate hits them.** Zero dependencies, one command, exits non-zero when something would break.

```console
$ pip install portacheck
$ portacheck --git          # scan everything tracked in this repo
```

## What it catches

| Code | Severity | Example | Why it breaks |
|---|---|---|---|
| `reserved_name` | error | `docs/CON.md`, `aux.py`, `COM¹.log` | Windows device names, with any extension, in any folder |
| `invalid_char` | error | `todo?.txt`, `a\b.txt`, `12:30.log` | `< > : " \| ? * \` and control chars are rejected by Windows |
| `trailing_dot` / `trailing_space` | error | `report.`, `notes ` | Windows strips them, so the file "disappears" or collides |
| `case_collision` | error | `src/Config.json` + `src/config.json` | one file on Windows (and default macOS); reported once, at the shallowest folder |
| `unicode_collision` | error | `café.png` (NFC) + `café.png` (NFD) | look identical, are distinct bytes; macOS treats them as one name |
| `component_too_long` | error | a 256-char file name | NTFS allows 255 UTF-16 units per name |
| `invalid_encoding` | error | a name that is not valid UTF-8 | Git for Windows cannot reproduce it |
| `path_length` | warn | deep `node_modules`-style trees | over 259 chars once cloned into a typical Windows folder |
| `invisible_char` | warn | `invoice\u202Egpj.exe` | bidi/zero-width characters make a name display as something else |
| `not_nfc` | warn | `café.png` in decomposed form | macOS/Linux tools may treat it as a different file |

## Demo

Synthetic paths piped in (nothing here is from a real repo):

```console
$ printf 'docs/CON.md\0src/Config.json\0src/config.json\0notes/todo?.txt\0build/report.\0' | portacheck --stdin0
ERROR case_collision     src/Config.json: paths differ only by case and cannot coexist on Windows: src/Config.json, src/config.json
ERROR invalid_char       notes/todo?.txt: 'todo?.txt' contains character(s) Windows rejects: '?'
ERROR reserved_name      docs/CON.md: 'CON.md' collides with the Windows device name CON
ERROR trailing_dot       build/report.: 'report.' ends with a dot — Windows silently strips it

4 error(s), 0 warning(s) — FAIL
```

Exit codes: `0` clean, `1` findings (warnings too with `--strict`), `2` setup problem — not a directory, not a git repo, git missing, or **nothing to scan** (so a broken checkout step can't silently pass; use `--allow-empty` if an empty input is expected).

## Where the paths come from

| Mode | Command | Scans |
|---|---|---|
| git index (recommended) | `portacheck --git [dir]` | tracked + staged paths, exactly what a clone gets — including names your OS could never create on disk |
| disk walk (default) | `portacheck [dir]` | every file/folder on disk; skips `.git`, `node_modules`, virtualenvs, caches (override with repeated `--skip`) |
| stdin | `git diff --name-only -z main... \| portacheck --stdin0` | any NUL-separated list of `/`-separated repo-relative paths |

## CI

GitHub Actions with inline PR annotations:

```yaml
- uses: actions/checkout@v4
- run: pip install portacheck
- run: portacheck --git --strict --format github
```

GitHub code scanning (SARIF 2.1.0):

```yaml
- run: portacheck --git --format sarif > portacheck.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: portacheck.sarif
```

pre-commit:

```yaml
- repo: https://github.com/calasdan-sketch/portacheck
  rev: v0.2.0   # use the tag you want
  hooks:
    - id: portacheck
```

## Options

```text
--git                 scan the git index instead of the disk
--stdin0              read NUL-separated paths from stdin
--format FORMAT       text (default), json, github, sarif   (--json still works)
--strict              warnings also fail
--ignore GLOB         drop findings whose path matches, e.g. 'tests/fixtures/*' (repeatable)
--prefix-len N        assumed length of the Windows clone folder, with trailing backslash (default 50)
--max-path N          Windows MAX_PATH, counting the terminating NUL (default 260)
--allow-empty         exit 0 when there is nothing to scan
```

**How path length is measured.** The length on *your* CI runner says nothing about Windows, so portacheck adds `--prefix-len` (default 50; `C:\Users\jane.doe\source\repos\project\` is 44) to each repo-relative path, counts UTF-16 units like Windows does, and warns at 260 or more (MAX_PATH includes the terminating NUL). Only the shallowest too-long folder is reported, with a count of what's inside it.

## How it compares

Only things stated in each project's own docs are listed; "—" means not listed there, not necessarily impossible.

| | portacheck | [pre-commit-hooks](https://github.com/pre-commit/pre-commit-hooks/blob/master/.pre-commit-hooks.yaml) `check-illegal-windows-names` + `check-case-conflict` | [git-path-audit](https://github.com/bunta-expert/git-path-audit) | [RepoPort](https://github.com/TohruSu/RepoPort/releases/tag/v0.1.0) | Git for Windows `core.protectNTFS` ([discussion](https://github.com/git-for-windows/git/issues/2777)) |
|---|---|---|---|---|---|
| Reserved names, invalid chars, trailing dot/space | yes | yes (one regex) | yes | yes | yes, refuses at checkout |
| Case collisions incl. folders | yes | yes ([since #575](https://github.com/pre-commit/pre-commit-hooks/pull/575)) | yes | yes | — |
| NFC/NFD collisions | yes | — | yes | yes | — |
| Bidi / invisible characters | yes | — | yes | — | — |
| Path length on Windows | yes (prefix-aware) | — | no (listed as a limitation) | — | — |
| Reads the git index | yes (`--git`) | staged files via pre-commit | yes | yes | n/a |
| Output | text, JSON, GitHub annotations, SARIF | offending file names | text, JSON, SARIF | text | error at clone time |
| Suppressions | `--ignore` globs | pre-commit `exclude` | no (listed as a limitation) | — | — |
| Runtime | Python 3.9+, no deps | pre-commit | Go 1.25+, Git 2.45+ | Python | — |

## Honest limits

- **Case folding is an approximation.** NTFS compares names with a per-volume uppercase table; portacheck uses Python's simple (1:1) uppercase mappings, which is close but not identical across Windows versions. It deliberately does *not* use full case folding, so `straße` and `strasse` are not flagged (NTFS keeps them apart).
- **macOS behaviour** (case-insensitive, normalization-insensitive by default) is modelled, not emulated per filesystem.
- **Not covered yet:** 8.3 short-name clashes (`PROGRA~1`), symlinks (which need extra setup on Windows), file contents, and per-line suppression comments.
- Long paths are warnings: Windows 10 1607+ and Git for Windows can opt into long paths ([`core.longpaths`, off by default](https://gitforwindows.org/git-cannot-create-a-file-or-directory-with-a-long-path.html)), but much tooling still breaks.
- Everything printed is escaped (control, bidi and zero-width characters, raw bytes), so a hostile file name can't rewrite your terminal or CI log.

Rule sources: Microsoft, [Naming Files, Paths, and Namespaces](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file).

## Python API

```python
from portacheck import scan_paths, scan_tree, git_paths

findings = scan_paths(["docs/CON.md", "src/ok.py"])   # pure, no filesystem
findings = scan_tree(".")                             # disk walk
findings = scan_paths(git_paths("."))                 # git index
for f in findings:
    print(f.severity, f.code, f.path, f.detail)
```

## License

MIT
