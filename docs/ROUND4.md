# Round 4: the stranger's first hour

Scope: what someone gets from `pip install portacheck` and the README. Branch `expert-2`. Nothing was published, tagged or pushed.

**Honesty note on the panel.** No sub-agent tool was available in this session, so the specialists below are roles one reviewer played one after another, each with real commands. They are not independent minds. The one outside check is the comparison with two other tools' own pages (read, not run).

## Baseline (before any change)
| What | Result |
|---|---|
| `pytest` from a fresh checkout | **fails to collect** (`No module named portacheck`) unless the package is installed or `PYTHONPATH=src` |
| `PYTHONPATH=src pytest` | 144 passed |
| PyPI (`pip index versions portacheck`, 2026-11-07) | only **0.1.0**; `portacheck --git` on it: `unrecognized arguments` |
| Repo version | 0.3.0 (0.2.0 and 0.3.0 never released) |

## Specialists and findings
| Specialist | Finding | Proof command |
|---|---|---|
| First-time user (README only, built wheel in clean venv, Python 3.9 and 3.13, folder with spaces) | Every README quick-start command works from the wheel. But `pip install portacheck` today gives 0.1.0 where `--git` does not exist | `python -m build`, `pip install --no-index dist/*.whl`, then `portacheck --git`, `--rev HEAD`, `--format gitmv`, `--stdin0`, `--explain`, `--list-codes`, `python -m portacheck --version` |
| Release engineer | wheel had no `py.typed`, no project URLs, one classifier set missing Python/OS; sdist lacked CHANGELOG and the hook file; `twine check` passes; no tests/secrets/personal paths in the wheel; entry point and LICENSE present | `unzip -l dist/*.whl`, `tar tzf dist/*.tar.gz`, `twine check` |
| Supply-chain reviewer | zero runtime dependencies (nothing to pin); git is called without a shell, with `core.fsmonitor=false`, option-looking refs refused (`--rev=--output=x` is refused, nothing written); no network use | `portacheck --rev=--output=/tmp/x`, `grep -n "shell=\|signal" src/portacheck/*.py` |
| Docs/DX writer | README install line hid the "PyPI is older" fact in a comment; pre-commit `rev` pointed at a tag that does not exist; `--help` did not list exit codes; errors showed `[Errno 2]` and `git rev-parse failed: exit 1` | `portacheck --rev nosuch`, `--baseline nope.json` |
| CI integrator | CI built the wheel but never installed it; no lint; fix-script line endings never checked | read `.github/workflows/ci.yml` (not run here) |
| Hostile-input fuzzer | 200 KB random bytes, 50 MB single name, 1M paths, 4M-component path, 6 concurrent `--write-baseline`: no crash, no traceback, baseline stayed valid. **Defect:** a malformed `[portacheck` header in a settings file is silently ignored on Python 3.9/3.10, so the run passes (tomllib on 3.11+ rejects it); duplicate keys too. `--max-path 0` accepted | 4000-case differential of the built-in reader vs `tomllib`, `portacheck --max-path 0` |
| Performance engineer | 1M paths 12 s, 4M-component path 1.7 s, one 50 MB name 11 s (linear, about 1 microsecond per character; not fixed, no real repo has this) | see fuzzer row |
| Windows reviewer (reading only) | `print` on Windows writes CRLF, so `--format gitmv > fix.sh` would not run under `sh`; legacy console code pages cannot show the long dash; Notepad adds a BOM to baseline/settings files; a volume with inode 0 would make the walk skip every folder after the first; closed pipe raises OSError there | read of `scan.py`, `cli.py`, `baseline.py`; simulated in `tests/test_round4.py` |
| Competitor's maintainer | git-path-audit (v0.0.1, Go 1.25+, Git 2.45+) and pre-commit-hooks: README comparison still matches their pages (read 2026-11-07, not run). git-path-audit lists no baselines, fixes, config, homoglyphs or path length; their Unicode case-fold collision check is a heuristic, ours uses simple uppercase only (see README limits) | WebFetch of both pages |

## Scored ideas (value / difference / effort / risk, 1-5; DONE or NOT-DONE)
| # | Idea | Value | Diff. | Effort | Risk | Status |
|---|---|---|---|---|---|---|
| 1 | Tests run from a fresh checkout (pytest pythonpath) | 4 | 1 | 1 | 1 | DONE |
| 2 | `py.typed` + Typed classifier | 3 | 1 | 1 | 1 | DONE |
| 3 | Project URLs, classifiers, MANIFEST (changelog, tests, hook file in sdist) | 4 | 1 | 1 | 1 | DONE |
| 4 | Version-agreement test (pyproject, `__version__`, changelog, README) | 4 | 2 | 1 | 1 | DONE |
| 5 | Settings reader parity with tomllib (bad header, duplicate key) | 5 | 3 | 2 | 1 | DONE |
| 6 | `--max-path` lower bound | 2 | 1 | 1 | 1 | DONE |
| 7 | Plain-English git and file errors | 4 | 2 | 1 | 1 | DONE |
| 8 | Exit codes in `--help` | 3 | 2 | 1 | 1 | DONE |
| 9 | LF-only stdout (fix script on Windows) | 5 | 3 | 1 | 1 | DONE (simulated) |
| 10 | Console code-page fallback instead of `?`/crash | 3 | 2 | 2 | 1 | DONE (simulated) |
| 11 | BOM tolerance for baseline/settings | 3 | 1 | 1 | 1 | DONE |
| 12 | Inode-0 guard in the walk | 3 | 1 | 1 | 2 | DONE (simulated) |
| 13 | Quiet exit on closed pipe (incl. Windows errno) | 2 | 1 | 1 | 1 | DONE |
| 14 | CI: lint, install the built wheel clean, check LF | 4 | 2 | 2 | 1 | DONE (workflow not run) |
| 15 | README: say plainly that PyPI is 0.1.0 | 5 | 1 | 1 | 1 | DONE |
| 16 | Reusable GitHub Action (`action.yml`) | 4 | 3 | 2 | 3 (needs a real runner and a release) | NOT-DONE |
| 17 | `\\?\` long-path prefix for disk walks on Windows | 3 | 2 | 3 | 4 (cannot test) | NOT-DONE |
| 18 | Faster handling of one enormous name | 1 | 1 | 2 | 2 | NOT-DONE |
| 19 | Per-line suppression comments / `.portacheckignore` | 3 | 3 | 4 | 3 | NOT-DONE (earlier "not built") |
| 20 | Full Unicode case folding option / NTFS `$MFT` names | 2 | 3 | 3 | 3 (no oracle) | NOT-DONE |
| 21 | Read `.gitmodules` of nested submodules | 2 | 3 | 4 | 3 | NOT-DONE |
| 22 | Real Windows/macOS run to confirm every Windows claim | 5 | 5 | n/a | 1 | NOT-DONE (needs a machine) |
| 23 | Trusted-publishing release workflow | 4 | 2 | 2 | 4 (publishing; must be Dan's decision) | NOT-DONE |

## What could not be tested
Windows and macOS (everything above marked "simulated" or "read" is unproven there); the CI workflow changes (no runner); Python 3.10-3.12 this round; Git versions other than 2.43; installing from the real PyPI after release.
