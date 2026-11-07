# Changelog

## 0.3.0 — unreleased

### Added in the third review round
- **`.gitmodules` checks** (`submodule_name`, `submodule_url`, `submodule_path`, `submodule_update`, `submodule_config`): the root `.gitmodules` is read from the index, a commit or the disk and checked for the tricks Git's own `git fsck` rejects (`..` in a name, a url starting with `-` or containing an encoded newline, a path starting with `-`, `update = !command`, a file over 1 MiB). Tested against `git fsck --strict` (Git 2.43) on a table of cases and on 400 random files in the benchmark. `ext::` urls and unparsable lines are warnings.
- `--rev REF`: scan the tree of a commit, branch or tag without checking it out (vet a PR head). `--git` now scans the **whole** repository even when pointed at a sub-folder (it used to list only that folder's files, so a `Docs/` vs `docs/` clash elsewhere was missed).
- Settings file: `.portacheck.toml` or `[tool.portacheck]` in `pyproject.toml`, plus `--config` / `--no-config`. A file found inside the scanned folder cannot disable or ignore the attack checks and cannot set `skip` or `allow_empty` (a pull request author controls it); a file named with `--config` is trusted.
- `--explain CODE` (why, fix, source) and SARIF `help` / `helpUri` per rule; `--format markdown` (for `$GITHUB_STEP_SUMMARY`); a `by code:` summary line in text output; `python -m portacheck`.
- New name checks: `component_bytes` (over 255 UTF-8 bytes: Linux `NAME_MAX`), `path_length_posix` (macOS 1024 / Linux 4096), `confusable_name` and `mixed_script` (Cyrillic/Greek look-alikes, ligatures, full-width forms), `os_junk` (`.DS_Store`, `Thumbs.db`, `desktop.ini`, `._*`).
- Warnings on stderr for an `--ignore` pattern that matched nothing, and for a settings-file pattern that was refused.
- `benchmarks/bench.py`: new hazard classes, a `.gitmodules` vs `git fsck` parity table, a hostile deep-path robustness test, `--prev-src` for a round-over-round comparison.

### Fixed in the third review round
- **Crash and memory**: a path with tens of thousands of components needed memory quadratic in its length (a 200,000-component path was killed by the OS); paths of 4,096+ bytes are now reported (`path_length_posix`, error) and kept out of the folder tree. Path-length collapsing is linear (was O(n x depth)).
- The disk walk was recursive: a 1,500-level folder tree raised `RecursionError`, which printed a traceback and exited 1, the same code as "findings". It is iterative now, a folder that cannot be read fails the run with exit 2 instead of being skipped, and any unexpected exception exits 2 ("nothing was verified"), never 1 or 0.
- A lone surrogate (Python API only) crashed JSON, SARIF and baseline output; `--write-baseline` is written atomically; the git calls ignore `core.fsmonitor`, take no index lock and never prompt or lazily fetch.
- Very long paths are clipped in text and GitHub output (JSON, SARIF and baselines keep them whole); `--stdin0` fed a newline-separated list says so.
- `.gitmodules` with a UTF-8 byte-order mark no longer hides a hazard; the baseline fingerprint of findings that share a code and path (several hazards in one `.gitmodules`) now includes an identity, existing baselines still match.

### Changed in the third review round (behaviour)
- A name of more than 255 UTF-8 bytes but at most 255 UTF-16 units (for example 100 CJK characters) is now a `component_bytes` warning (one existing test asserted it was clean).
- `--git` on a sub-folder scans the whole repository (see above); `--strict` runs can see new warnings (`os_junk`, `confusable_name`, `mixed_script`, `component_bytes`, `path_length_posix`); `--disable CODE` restores the old result.

### Added
- **Git-metadata guard** (`git_dir_alias`, `git_meta_alias`): ports Git's own `is_ntfs_dotgit*` / `is_hfs_dotgit*` predicates. Catches `.git` reached as `.git . .`, `git~1`, `.git::$INDEX_ALLOCATION`, HFS+-ignorable characters, in any folder, plus forged spellings of `.gitmodules`, `.gitattributes`, `.gitignore`, `.mailmap` (including `gi7eba~1`-style hash short names). Cross-checked against a real Git in the tests and in the benchmark (zero disagreements on 3,000 random names).
- **8.3 short-name collisions** (`short_name_collision`): `longfilename.txt` beside `LONGFI~1.TXT`.
- **Symlink analysis** from the git index (`git ls-files --stage` + `cat-file --batch`) or the disk: `symlink`, `symlink_meta`, `symlink_traversal`, `symlink_escape`, `symlink_backslash`.
- `--format gitmv`: reviewable `git mv` fix script (display-safe quoting, deepest first, never renames Git-metadata names).
- `--baseline FILE` / `--write-baseline FILE`, `--new-since REF` (index vs a base ref, with new-folder detection), `--disable CODE`, `--list-codes`.
- SARIF: `partialFingerprints` and `relatedLocations` for collisions. JSON: `paths` lists every member of a collision.
- `benchmarks/bench.py` and committed `benchmarks/RESULTS.md`: accuracy on a generated hostile/benign corpus against pre-commit-hooks and Git, a Git-parity fuzz, and a 500,000-file speed test. Tests gate the corpus (no false positives, all hostile cases caught).
- Python API: `git_entries()`, `short_name_collisions()`; `scan_paths(..., symlinks=, on_disk=)`; `Finding.paths`.

### Changed (behaviour)
- **Tracked/on-disk symlinks now produce a `symlink` warning** (and `symlink_escape` for absolute or out-of-repo targets). `--strict` runs on repos with symlinks will start failing: use `--disable symlink` (and `--disable symlink_escape`) to restore the old result.
- A path component that is `.git` (or any alias) in the git index or a path list is an error. A real `.git` folder in a disk walk is still ignored.
- Collision detection groups siblings per folder instead of folding every full path; results are the same, 2.9x faster on 500,000 files (6.9 s to 2.4 s) and about half the memory.

## 0.2.0 — unreleased

### Added
- `--git`: scan tracked + staged paths straight from the git index (what a clone gets, including names that cannot exist on your disk).
- `--stdin0`: scan any NUL-separated path list (e.g. `git diff --name-only -z`).
- `--format github` (inline PR annotations) and `--format sarif` (SARIF 2.1.0 for code scanning); `--json` kept as an alias of `--format json`.
- `unicode_collision` (NFC/NFD names that are one file on macOS), `not_nfc` and `invisible_char` (bidi/zero-width characters) checks.
- `invalid_encoding` for names that are not valid UTF-8.
- `--ignore GLOB` suppressions, `--allow-empty`, `.pre-commit-hooks.yaml`, `scan_paths()` / `git_paths()` / `unicode_collisions()` API.

### Fixed
- Backslash (`\`) in a name is now an `invalid_char` (legal on Linux, a separator on Windows).
- `COM¹ COM² COM³ LPT¹ LPT² LPT³` are reserved, per Microsoft's naming docs.
- Case collisions no longer use full case folding: `straße` vs `strasse` was a false positive (NTFS keeps them apart).
- A folder clash (`Src/` vs `src/`) is reported once instead of once per file inside it.
- Component length counts UTF-16 units like NTFS (emoji count 2).
- All printed output escapes control, bidi and zero-width characters and raw bytes from untrusted names.
- Path-length summary is O(n·depth) instead of quadratic on huge trees.

### Changed (behaviour)
- **Path length** is now measured as it would be on Windows: `--prefix-len` (default 50) + the repo-relative path, warning at 260+ for files (MAX_PATH includes the NUL) and 248+ for folders (Git for Windows' CreateDirectory limit). Previously it used the absolute path of the machine running the scan, which says nothing about a Windows clone. Only the shallowest too-long path is reported.
- **Nothing to scan now exits 2** (fail closed: an empty or mis-checked-out directory used to pass). Use `--allow-empty` for the old behaviour.
- JSON output gains a `scanned` count and a lossless `path_raw_b64` per finding; existing keys are unchanged.
- `CON .txt` is now reserved (it was asserted as allowed in 0.1.0's tests; Git for Windows refuses it).

### Fixed after independent panel review
- Reserved names now match Git for Windows' `is_valid_win32_path` (compat/mingw.c) as well as Microsoft's list: spaces before an extension or `:stream` (`CON .txt`, `AUX  .tar.gz`), `CONIN$`, `CONOUT$` and `LPT0`. `COM0` stays allowed.
- A case clash between siblings (`src/Config` vs `src/config`) is no longer hidden when the parent folder also clashes (`Src/` vs `src/`).
- Folder length limit is 248 (was 260).
- README / `--help` example: `C:\Users\jane.doe\source\repos\project\` is 39 chars, not 44.
- Removed an unreproducible "5-8x faster" claim (it compared two in-progress builds, not 0.1.0).
- SARIF URIs percent-encode the real bytes of undecodable names (`bad%FF.txt`); JSON adds `path_raw_b64`.
- `.` / `..` components (e.g. `../x` on `--stdin0`) are no longer reported as trailing dots.
- CJK compatibility ideographs (U+F900–U+FAFF, U+2F800–U+2FA1F) no longer trigger `not_nfc` / `unicode_collision`; HFS+ excludes them from normalization (APFS behaviour unverified).
- `invalid_encoding` details show raw bytes as `\xNN`, the same as the path column.
- Collision details escape bidi/control characters in every format (JSON and SARIF too, not only text).
- README `git diff` example uses `--diff-filter=d` and states that a diff cannot see collisions with unchanged files.

## 0.1.0
- Initial release.
