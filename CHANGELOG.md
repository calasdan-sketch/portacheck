# Changelog

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
- 5-8x faster on large trees (ASCII fast paths); path-length summary is O(n·depth).

### Changed (behaviour)
- **Path length** is now measured as it would be on Windows: `--prefix-len` (default 50) + the repo-relative path, for files as well as folders, warning at 260+ (MAX_PATH includes the NUL). Previously it used the absolute path of the machine running the scan, which says nothing about a Windows clone. Only the shallowest too-long path is reported.
- **Nothing to scan now exits 2** (fail closed: an empty or mis-checked-out directory used to pass). Use `--allow-empty` for the old behaviour.
- JSON output gains a `scanned` count; existing keys are unchanged.

## 0.1.0
- Initial release.
