# portacheck

**Your repo works on Windows — until a contributor checks it out on Windows.** Scan any repo for the path hazards that break Windows checkouts, and fail CI before they land:

- **Reserved device names** — `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, in any path component, with or without an extension (`aux.py` is unusable)
- **Invalid characters** — `< > : " | ? *` and control characters in names
- **Trailing dot or space** — `report.` and `report ` get silently mangled by Windows
- **Case-insensitive collisions** — `Config.json` and `config.json` can both exist on NTFS but not in the same git checkout
- **Over-long paths and components** — past the 260-char MAX_PATH or the 255-char component limit

## Install

```bash
pip install portacheck
```

## Usage

```bash
portacheck .                     # scan current directory
portacheck path/to/repo --json   # machine-readable findings
portacheck . --strict            # warnings (long paths) also fail
```

Exit codes: `0` clean, `1` findings, `2` usage error. Output:

```
ERROR case_collision    src/config.json: paths differ only by case and cannot coexist on Windows: src/Config.json, src/config.json
ERROR reserved_name     lib/aux/mod.py: 'mod.py' ... (component 'aux' collides with the Windows device name AUX)
WARN  path_length       src/very/deep: directory path is 271 chars (> 260)...

3 error(s), 1 warning(s) — FAIL
```

`.git`, `node_modules`, virtualenvs and caches are skipped by default; override with repeated `--skip` flags (use `--skip` with a value you fully specify; there is no "add to defaults" mode).

## CI

```yaml
- run: pip install portacheck
- run: portacheck . --strict
```

Cheap enough to run on every PR: it's a single tree walk, no subprocesses.

## Notes

- Name rules are pure functions (`check_component`, `check_relpath`) — unit-testable without touching a filesystem, and usable as a pre-commit hook for staged paths.
- Long paths are warnings by default: Windows 10+ can opt into long-path support, but plenty of tooling (old zipper libs, some antivirus hooks, cmd.exe scripts) still truncates. `--strict` makes them fail.
- Runs anywhere: Linux CI runners catch Windows hazards before a Windows user ever hits them.

## License

MIT-style: use it, ship it, no warranty.
