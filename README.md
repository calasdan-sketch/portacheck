# portacheck

**Catch file names that break Windows and macOS checkouts, or that attack them, in CI on Linux, before a teammate hits them.** Zero dependencies, one command, exits non-zero when something would break, and prints the `git mv` commands that fix it. It also reads a repository's `.gitmodules` for the submodule tricks Git itself refuses, and can vet a branch or pull-request head without checking it out.

```console
$ pip install portacheck    # PyPI still has 0.1.0 (checked 2026-11-07), which has no --git; this README is for 0.3.0. Until it is released: pip install git+https://github.com/calasdan-sketch/portacheck
$ portacheck --git          # scan everything tracked in this repo
$ portacheck --git --format gitmv > fix.sh   # review it, then run it: git mv commands for what a rename can fix
$ portacheck --rev origin/some-branch       # vet a branch, tag or PR head straight from the object store, no checkout
$ python -m portacheck --explain case_collision   # why a finding matters and how to fix it
```

## What it catches

| Code | Severity | Example | Why it breaks |
|---|---|---|---|
| `reserved_name` | error | `docs/CON.md`, `aux.py`, `CON .txt`, `COM¹.log`, `CONIN$`, `LPT0` | Windows device names, with any extension, trailing spaces or `:stream`, in any folder (union of [Microsoft's list](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file) and [Git for Windows' `is_valid_win32_path`](https://github.com/git-for-windows/git/blob/main/compat/mingw.c)) |
| `invalid_char` | error | `todo?.txt`, `a\b.txt`, `12:30.log` | `< > : " \| ? * \` and control chars are rejected by Windows |
| `trailing_dot` / `trailing_space` | error | `report.`, `notes ` | Windows strips them, so the file "disappears" or collides |
| `case_collision` | error | `src/Config.json` + `src/config.json` | one file on Windows (and default macOS); a folder clash is reported once at the folder; clashes between siblings inside it are reported separately |
| `unicode_collision` | error | `café.png` (NFC) + `café.png` (NFD) | look identical, are distinct bytes; macOS treats them as one name |
| `component_too_long` | error | a 256-char file name | NTFS allows 255 UTF-16 units per name |
| `invalid_encoding` | error | a name that is not valid UTF-8 | Git for Windows cannot reproduce it |
| `path_length` | warn | deep `node_modules`-style trees | over 259 chars once cloned into a typical Windows folder |
| `git_dir_alias` | error | `git~1/hooks/post-checkout`, `.git . ./x`, `.git::$INDEX_ALLOCATION/x`, `.g<ZWNJ>it/x` | on Windows/macOS these resolve to the repo's own `.git`; a checkout through one can overwrite `.git/hooks` and run code (Git itself refuses them since [CVE-2014-9390](https://nvd.nist.gov/vuln/detail/CVE-2014-9390); portacheck catches them in the tree *before* a clone does) |
| `git_meta_alias` | error / warn | `.GitModules`, `GITMOD~1`, `gi7eba~1`, `.gitmodules ` | non-canonical spellings of `.gitmodules` / `.gitattributes` (error) or `.gitignore` / `.mailmap` (warn) that Git reads as the real file on case- or alias-insensitive filesystems |
| `dotdot_component`, `dot_component` | error | a git tree entry named `..`, `.` or empty (`--git` / `--rev` only) | `git fsck` calls these hasDotdot / hasDot / emptyName and Git refuses to check them out; a hand-made tree can still hold them. Not applied to `--stdin0`, where `../x` is an ordinary relative path |
| `short_name_collision` | error | `longfilename.txt` + `LONGFI~1.TXT` | NTFS gives long names a hidden 8.3 alias; a tracked file that *is* that alias clashes with it (when short names are enabled) |
| `symlink` | warn | any tracked symlink | on Windows it needs Developer Mode/admin plus `core.symlinks=true`; otherwise [Git checks it out as a small text file](https://git-scm.com/docs/git-config) |
| `symlink_meta` / `symlink_traversal` | error | symlink named `.gitmodules`; `lnk/inner` below tracked symlink `lnk` | a link where Git expects a file, or a path written through a link, redirects the checkout |
| `symlink_escape` / `symlink_backslash` | warn | target `../../etc/passwd`, `/abs`, `C:\x`, `a\b` | link points outside the repo or uses a backslash separator |
| `component_bytes` | warn | 100 CJK characters (300 UTF-8 bytes) | NTFS counts UTF-16 units, but Linux file systems allow 255 *bytes* (`NAME_MAX`), so the name cannot exist there (macOS/APFS limit not verified here) |
| `path_length_posix` | warn / error | a relative path of 1,023+ bytes (warn) or 4,096+ bytes (error) | macOS `PATH_MAX` is 1024 and Linux's 4096 (both count the NUL; macOS value from `sys/syslimits.h`, not run on macOS here); the clone folder comes on top. 4,096+ byte paths are also kept out of the collision checks |
| `confusable_name` / `mixed_script` | warn | `README.md` beside `R<Cyrillic Е>ADME.md`; `p<Cyrillic а>ypal.js`; `ﬁle.txt` beside `file.txt` | different files that look the same to a reviewer. Uses a small curated subset of Unicode's confusables, so it is not exhaustive |
| `os_junk` | warn | `.DS_Store`, `Thumbs.db`, `desktop.ini`, `._name` | Finder/Explorer metadata committed by accident |
| `submodule_name` / `submodule_url` / `submodule_path` / `submodule_update` / `submodule_config` | error (url `ext::` and unparsable lines warn) | `.gitmodules` with name `../evil` ([CVE-2018-11235](https://nvd.nist.gov/vuln/detail/CVE-2018-11235)), url `-oProxyCommand=…` ([CVE-2017-1000117](https://nvd.nist.gov/vuln/detail/CVE-2017-1000117)), a url with `%0a`, path `-x`, `update = !cmd` | the rules of Git's own `git fsck` (`gitmodulesName`, `gitmodulesUrl`, `gitmodulesPath`, `gitmodulesUpdate`), checked on the root `.gitmodules` before you clone. Compared with `git fsck --strict` (Git 2.43) in the tests and the benchmark |
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
| git index (recommended) | `portacheck --git [dir]` | the **whole repository's** tracked + staged paths (also when `dir` is a sub-folder), exactly what a clone gets — including names your OS could never create on disk |
| a commit | `portacheck --rev REF [dir]` | the tree of a commit, branch or tag without checking it out: vet a pull-request head or a release before anyone clones it |
| disk walk (default) | `portacheck [dir]` | every file/folder on disk; skips `.git`, `node_modules`, virtualenvs, caches (override with repeated `--skip`) |
| stdin | `git diff --name-only -z --diff-filter=d main... \| portacheck --stdin0` | any NUL-separated list of `/`-separated repo-relative paths (`--diff-filter=d` drops deleted files). A diff only sees changed paths, so it **cannot catch a collision with a file that did not change** — use `--git` for that |

## Adopt it on a repo that already has findings

```console
$ portacheck --git --write-baseline .portacheck-baseline.json      # record today's debt, exit 0
$ portacheck --git --baseline .portacheck-baseline.json --strict   # fail only on NEW findings
$ portacheck --git --new-since origin/main --strict                # only paths added since the base branch
```

A baseline entry is the finding code plus the exact bytes of the path, so rewording a message never resurrects old debt. A malformed or missing baseline file is a setup error (exit 2), never a silent pass. `--new-since REF` still finds a new file that collides with an old one, but does not blame a pull request for names that were already there. `--disable CODE` turns a check off (`--list-codes` shows them), e.g. `--disable symlink` for a repo that needs links.

## Settings file

Repeating flags in every CI job gets old. Put them in `.portacheck.toml` (table `[portacheck]`) or in `pyproject.toml` (table `[tool.portacheck]`) in the scanned folder:

```toml
[portacheck]
disable = ["symlink", "os_junk"]
ignore = ["tests/fixtures/*"]
prefix_len = 39
strict = true
```

Keys: `disable`, `ignore`, `skip`, `prefix_len`, `max_path`, `strict`, `allow_empty`. Flags override scalar settings and add to lists. A malformed file or unknown key is a setup error (exit 2).

**Trust model.** Whoever writes a pull request controls the files in it, settings file included. So a settings file *found* in the scanned folder may not `disable` or `ignore` the attack checks (`git_dir_alias`, `git_meta_alias`, `symlink_*`, `reserved_name`, `submodule_*`, `invalid_encoding`, `path_length_posix`; the run fails with exit 2 and says so) and may not set `skip` or `allow_empty`. A file named with `--config` is trusted as given: for pull requests from forks, take it, and your `--baseline`, from the base branch, not from the PR.

## CI

GitHub Actions with inline PR annotations:

```yaml
- uses: actions/checkout@v4
- run: pip install portacheck
- run: portacheck --git --strict --format github
- if: always()   # a readable table on the run page, even when the step above failed
  run: portacheck --git --format markdown >> "$GITHUB_STEP_SUMMARY" || true
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
  rev: v0.3.0   # the tag does not exist yet: it is created when 0.3.0 is released
  hooks:
    - id: portacheck
```

## Options

```text
--git                 scan the whole git index instead of the disk
--rev REF             scan the tree of a commit/branch/tag without checking it out
--stdin0              read NUL-separated paths from stdin
--format FORMAT       text (default), json, github, sarif, markdown, gitmv   (--json still works)
--explain CODE        why a finding matters and how to fix it (--list-codes lists them)
--config FILE         a settings file you trust;  --no-config ignores any found file
--strict              warnings also fail
--ignore GLOB         drop findings whose path matches, e.g. 'tests/fixtures/*' (repeatable)
--only GLOB           report only findings under this glob, e.g. 'packages/web/*' (monorepo team view; the whole
                      repository is still scanned, so a clash with another folder is still found)
--prefix-len N        assumed length of the Windows clone folder, with trailing backslash (default 50)
--max-path N          Windows MAX_PATH, counting the terminating NUL (default 260)
--allow-empty         exit 0 when there is nothing to scan
--format gitmv        print a reviewable script of `git mv` fixes (never renames anything itself)
--baseline FILE       hide findings recorded in FILE;  --write-baseline FILE records them
--new-since REF       with --git: only findings involving paths added since REF
--disable CODE        turn a check off (repeatable);  --list-codes lists them
```

**Fix script.** `--format gitmv` writes `git mv -- old new` lines, deepest paths first so a child moves before its folder, with names made safe (`CON.txt` becomes `CON_.txt`, `a?b` becomes `a_b`, invisible characters are dropped, NFD becomes NFC, collisions get `_2`). Names containing control, bidi or raw bytes use bash `$'...'` quoting with `\uXXXX` escapes, so the script is safe to view and run. Git-metadata names and symlinks are listed as `# manual:` lines, never renamed (renaming `.git .` to `.git` would be the attack itself). It does not fix references to the old names (imports, docs, CI).

**How path length is measured.** The length on *your* CI runner says nothing about Windows, so portacheck adds `--prefix-len` (default 50; `C:\Users\jane.doe\source\repos\project\` is 39) to each repo-relative path, counts UTF-16 units like Windows does, and warns when a file reaches 260 (MAX_PATH includes the terminating NUL) or a folder reaches 248 (MAX_PATH minus room for an 8.3 name — the limit Git for Windows applies when it creates folders). Only the shallowest too-long path is reported, with a count of what's inside it. In a disk walk an empty folder is measured as a file.

## Benchmark

`python benchmarks/bench.py` regenerates everything below and the full tables in [`benchmarks/RESULTS.md`](benchmarks/RESULTS.md). Cases are labelled by how they are built from a known rule (never by any tool's output); Linux Git 2.43, Python 3.13, one machine, so treat the seconds as relative.

| 288 hostile + 2,071 benign names | precision | recall | F1 |
|---|---|---|---|
| portacheck 0.3.0 (this tree) | 1.000 | 1.000 | 1.000 |
| portacheck 0.3.0 before the third review round | 1.000 | 0.965 | 0.982 |
| portacheck 0.2.0 | 1.000 | 0.882 | 0.937 |
| pre-commit `check-illegal-windows-names` regex | 1.000 | 0.493 | 0.660 |
| pre-commit `check-case-conflict` | 1.000 | 0.062 | 0.118 |
| Linux `git` with `core.protectNTFS`/`protectHFS` (only guards `.git`; Git for Windows also refuses device names at checkout, not measured here) | 1.000 | 0.115 | 0.206 |

**Read the 1.000 honestly:** the corpus is written by the same authors as the rules, so it shows coverage and no regressions, not that no other hostile name exists. This round added two hazard classes to the corpus (names over 255 UTF-8 bytes, look-alike names) together with the checks for them, so the jump from 0.965 to 1.000 is the new classes being covered, not the old ones getting better. Two checks that do not depend on our own labels: for 3,000 random near-misses of Git's `.git` synonyms, real Git and portacheck agree on all of them (319 rejected by both, 0 disagreements); and for 400 random `.gitmodules` files, `git fsck --strict` (Git 2.43) and portacheck agree on all of them (332 hostile for both, 0 disagreements; 7 of the 68 clean ones carry a portacheck warning, such as the `ext::` transport, that fsck does not check).

| 500,000 tracked files (33k folders), fresh process, a busy 2-core machine | seconds (median of 3) | peak RSS |
|---|---|---|
| portacheck 0.3.0 (this tree) | 9.2 | 251 MB |
| portacheck 0.3.0 before the third review round | 9.0 | 251 MB |
| portacheck 0.2.0 | 27.4 | 405 MB |
| pre-commit illegal-names regex, regex only | 20.2 | n/a |

The machine was shared and loaded while these ran, so only the ratios mean anything: this round did not change the speed (an in-process comparison alternating the two trees was within noise), and the earlier run of the same table on a quieter machine gave 2.4 s for 0.3.0 and 6.9 s for 0.2.0. A single hostile path with 3,000 components (6,001 bytes) takes 0.07 s now and took 9.2 s before this round; one with 200,000 components was killed by the operating system for lack of memory before this round and is now reported in milliseconds.

Round 4 re-ran the benchmark against the round-3 tree on a quieter machine: accuracy identical, 4.15 s vs 4.32 s median for 500,000 files, 250 MB both (no speed change; see `benchmarks/RESULTS.md`).

Real repository check (measured in the previous round, not repeated since): the Linux kernel tree (97,360 files, shallow clone, `git ls-tree` piped to `--stdin0`) scans in 0.4 s (0.9 s on 0.2.0) with the same 13 case collisions on both versions (such as `xt_CONNMARK.h` / `xt_connmark.h`) and no new false positives.

## How it compares

Only things stated in each project's own docs are listed (read 2026-11-07); "—" means not listed there, not necessarily impossible.

| | portacheck | [pre-commit-hooks](https://github.com/pre-commit/pre-commit-hooks/blob/master/.pre-commit-hooks.yaml) `check-illegal-windows-names` + `check-case-conflict` | [git-path-audit](https://github.com/bunta-expert/git-path-audit) | [RepoPort](https://github.com/TohruSu/RepoPort/releases/tag/v0.1.0) | Git for Windows `core.protectNTFS` ([discussion](https://github.com/git-for-windows/git/issues/2777)) |
|---|---|---|---|---|---|
| Reserved names, invalid chars, trailing dot/space | yes | yes (one regex) | yes | yes | yes, refuses at checkout |
| Case collisions incl. folders | yes | yes ([since #575](https://github.com/pre-commit/pre-commit-hooks/pull/575)) | yes | yes | — |
| NFC/NFD collisions | yes | — | yes | yes | — |
| Bidi / invisible characters | yes | — | yes | — | — |
| `.git` / `.gitmodules` aliases (`git~1`, streams, HFS+ ignorables) | yes | — | — | — | yes for `.git`, refuses at checkout |
| 8.3 short-name clashes, symlink hazards | yes | — | — | — | — |
| `.gitmodules` content (`..` names, `-` urls, `update = !cmd`) | yes (root file, rules of `git fsck`) | — | — | — | Git's `fsck` rejects them when objects are received, not before you clone |
| Scan a commit or tag without checkout | `--rev REF` | — | `--tree REV` | — | n/a |
| Explain a finding | `--explain CODE`, SARIF help text | — | rule catalog with stable IDs and a help URI | — | — |
| Fix output, baseline, new-only mode | `git mv` script, `--baseline`, `--new-since` | — | — (read-only by design) | text hint per finding | — |
| Path length on Windows | yes (prefix-aware) | — | no (listed as a limitation) | — | — |
| Reads the git index | yes (`--git`) | staged files via pre-commit | yes | yes | n/a |
| Output | text, JSON, GitHub annotations, SARIF | offending file names | text, JSON, SARIF | text | error at clone time |
| Suppressions, settings | `--ignore` globs, `.portacheck.toml` / `[tool.portacheck]` (cannot switch off attack checks when found in the scanned folder) | pre-commit `exclude` | no (listed as a limitation) | — | — |
| Runtime | Python 3.9+, no deps | pre-commit | Go 1.25+, Git 2.45+ | Python | — |

## Honest limits

- **Case folding is an approximation.** NTFS compares names with a per-volume uppercase table; portacheck uses Python's simple (1:1) uppercase mappings, which is close but not identical across Windows versions. It deliberately does *not* use full case folding, so `straße` and `strasse` are not flagged (NTFS keeps them apart).
- **macOS behaviour** (case-insensitive, normalization-insensitive by default) is modelled, not emulated per filesystem.
- **8.3 short names are modelled, not emulated:** only the first-six-letters rule for ASCII names, and only when short-name creation is on (Git's own source says "at least on the C: drive by default"). Non-ASCII long names are skipped. `.git` and its siblings are checked with a port of Git's own predicates.
- **Never run on real Windows or macOS here.** Windows and macOS behaviour comes from Microsoft's docs, Git's source (`path.c`, `compat/mingw.c`) and a Linux Git used as an oracle for the `.git` checks; no NTFS, ReFS, OneDrive or APFS volume was available. Other `.git` synonyms (for instance full Unicode case folding on HFS+) may exist that Git itself does not list.
- **Not covered yet:** OneDrive/SharePoint-only restrictions, `core.protectNTFS` interaction with sparse checkouts, submodule contents, file contents other than the root `.gitmodules` (for example `.gitattributes` filters), NTFS system-file names such as `$MFT` (not in the sources used here, so neither confirmed nor checked), and per-line suppression comments.
- **Reading the git index costs one `git ls-files` plus one `git cat-file --batch` for symlinks only.** In a shallow or partial clone a symlink target may be missing; the link is still reported, its target is not checked.
- Long paths are warnings: Windows 10 1607+ and Git for Windows can opt into long paths ([`core.longpaths`, off by default](https://gitforwindows.org/git-cannot-create-a-file-or-directory-with-a-long-path.html)), but much tooling still breaks.
- **Look-alike detection is a small curated subset** of Unicode's confusables (44 Cyrillic and Greek letters, plus NFKC for ligatures and full-width forms). Two names that differ only by a character outside that set are not flagged, and `l`/`I`/`1`-style ASCII look-alikes are deliberately ignored.
- **`.gitmodules`:** only the root file, and only the rules listed above, compared with the `git fsck` of Git 2.43 (the only version available here); newer Git versions may check more. The submodules' own contents are not read. A byte-order mark is stripped before parsing (Git's fsck reports such a file as unparsable; portacheck still checks it).
- **Byte limits:** `NAME_MAX` 255 bytes on Linux and `PATH_MAX` 4096 are Linux facts; macOS's 1024-byte `PATH_MAX` is from `sys/syslimits.h` and the APFS name limit is not verified. Only the repo-relative part of a path is measured. Paths of 4,096+ bytes are reported but left out of the collision checks (they would cost memory quadratic in their length).
- **Wrong repository.** Git lets an inherited `GIT_DIR`, `GIT_WORK_TREE` or `GIT_COMMON_DIR` win over the folder you name. portacheck compares the two and exits 2 with a plain message when they point at different repositories, instead of reporting on the wrong one. `GIT_INDEX_FILE` (set by Git while it runs a pre-commit hook) is honoured on purpose.
- **Trust:** a baseline or settings file stored in the repository you scan is written by that repository's authors. Take them from the base branch when checking pull requests from forks (see Settings file).
- **Tested on:** Linux with Git 2.43: the test suite on Python 3.9 and 3.13 (188 tests), and the built wheel installed into clean virtual environments on 3.9 and 3.13. 3.10-3.12 are not run this round. **Never run on Windows or macOS.** Windows behaviour was reviewed by reading the code (path separators, line endings, console encodings, `os.replace`, closed pipes, volumes that report inode 0) and the Windows-shaped parts are simulated in tests; `.github/workflows/ci.yml` runs the suite on Windows, and that run has not been seen yet. Paths longer than 259 characters in a *disk walk* on Windows may fail to open (`--git` and `--rev` do not walk the disk); the run then exits 2 rather than passing.
- **Memory:** about 0.45 KB per tracked path (218 MB for 500,000 files).
- Everything printed is escaped (control, bidi and zero-width characters, raw bytes), so a hostile file name can't rewrite your terminal or CI log.

Rule sources: Microsoft, [Naming Files, Paths, and Namespaces](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file).

## Python API

```python
from portacheck import scan_paths, scan_tree, git_paths, git_entries

findings = scan_paths(["docs/CON.md", "src/ok.py"])   # pure, no filesystem
findings = scan_tree(".")                             # disk walk
findings = scan_paths(git_paths("."))                 # git index
paths, links = git_entries(".")                       # git index + tracked symlinks and their targets
findings = scan_paths(paths, symlinks=links)
for f in findings:
    print(f.severity, f.code, f.path, f.detail)
```

## License

MIT, Copyright (c) 2026 Calas Automations Inc. Maintained by Calas Automations Inc.
