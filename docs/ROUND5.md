# Round 5: file-system, git-internals and monorepo specialists

Branch `expert-2`. Nothing was published, tagged or pushed.

**Honesty note.** No sub-agent tool was available, so the specialists are roles played in sequence by one reviewer, each with real commands. They are not independent minds. Outside checks: the two competitor pages (read, not run) and real Git 2.43 as an oracle.

## Author line
The maintainer name everywhere is "Calas Automations Inc." (pyproject `authors` and `maintainers`, LICENSE, `__author__`, `--version`, SARIF `organization`). The old handle now appears only inside real GitHub addresses; `tests/test_round5.py` pins both facts. No email was added.

## Baseline (before any change)
`pytest`: 172 passed. mypy (installed in scratch only): 4 errors. ruff: clean. 0.1.0 from PyPI downloaded read-only for the upgrade test.

## Upgrade path (registry 0.1.0 to this tree)
| Check | Result | Command |
|---|---|---|
| 0.1.0 CLI flags still work (`path`, `--max-path`, `--skip`, `--strict`, `--json`) | yes | `v1/bin/portacheck . --max-path 50 --skip Docs --strict` vs this tree: both exit 1 |
| 0.1.0 `--json` keys | this tree adds `scanned`; nothing removed | diff of the two JSON files |
| Same findings | one difference: 0.1.0 also listed `Docs/X` under the colliding folder `Docs` (4 errors vs 3); intended since round 2 | same fixture |
| Baseline written by the first 0.3.0 build still matches | yes, "baseline hid 3 existing finding(s)" | `--write-baseline` from commit 66d6d3a, read by this tree. 0.2.0 had no baselines, and no settings files existed before 0.3.0 |

## Specialists and findings
| Specialist | Finding | Proof command |
|---|---|---|
| Cross-platform filesystem engineer | Case, NFC/NFD, folder-vs-file and gitlink-vs-folder clashes (`Foo` + `foo/bar`, `vendor` gitlink + `Vendor/lib.c`) are all caught. Fix script robust: 253 random hostile repos, each fix script run with `sh -e`, rescan left 0 errors | `printf 'Foo\0foo/bar\0' \| portacheck --stdin0`; a scratch loop over random names |
| Git internals expert | **Defect (fail-open):** a tree with a `..` entry (made with `git mktree`, which `git fsck` rejects as hasDotdot) passed `--rev`, and `.` / empty names were silently tidied away. Fixed: `dotdot_component`, `dot_component`. **Defect (fail-open):** inherited `GIT_DIR` of another repo made `portacheck --git OTHER` scan the wrong repo and PASS (OTHER held `CON.txt`). Fixed: exit 2 with a plain message. Linked worktrees and a hook-style `GIT_DIR` of the same repo still work | `git mktree`, `git fsck --strict`, `GIT_DIR=a/.git portacheck --git b` |
| Monorepo maintainer | `--git` scans the whole repo, so a team could not see only its folder. Added `--only GLOB` (the repo is still fully scanned, collisions with other folders still found). Nested submodule contents still not read | `printf 'pkg/a/CON\0pkg/b/x\0pkg/b/X\0' \| portacheck --stdin0 --only 'pkg/a/*'` |
| QA / test-methodology expert | Seeded properties (order, duplicates, case collisions vs brute force, no raw control or bidi in any format) hold; the same properties with hypothesis, 1,500 examples each, found nothing. Mutation sanity: 19 of 20 flips caught, the survivor (255 vs 256 bytes) got a test. Golden files added for text, json, sarif, markdown, github, gitmv | `python benchmarks/mutation.py`, scratch hypothesis run |
| Type-checking reviewer | 4 mypy complaints (a possible `None.close()`, two untyped spots) fixed; mypy now clean | `mypy src` |
| Competitor's maintainer | git-path-audit v0.0.1 (read 2026-11-08, not run) now lists "empty or traversal-like components" (GPA002), a gap this round closes for git sources; it still lists no path length, baselines, config, `.git` aliases, submodules or symlinks. pre-commit-hooks: same hooks as before, no Unicode check | WebFetch of both pages |

## Scored ideas (value / difference / effort / risk, 1-5)
| # | Idea | V | D | E | R | Status |
|---|---|---|---|---|---|---|
| 1 | Author line "Calas Automations Inc." plus pinning test | 5 | 1 | 1 | 1 | DONE |
| 2 | Refuse a `GIT_DIR` that points at another repo | 5 | 3 | 2 | 1 | DONE |
| 3 | `..` / `.` / empty components in git trees | 4 | 4 | 1 | 1 | DONE |
| 4 | `--only GLOB` for monorepo teams | 4 | 3 | 1 | 1 | DONE |
| 5 | Golden files for every output format | 4 | 1 | 2 | 1 | DONE |
| 6 | Seeded property tests (+ hypothesis when installed) | 4 | 2 | 2 | 1 | DONE |
| 7 | Mutation sanity script | 3 | 2 | 2 | 1 | DONE |
| 8 | Boundary test for the 255-byte limit | 2 | 1 | 1 | 1 | DONE |
| 9 | mypy-clean source | 2 | 1 | 1 | 1 | DONE |
| 10 | Fix script: do not rename both members of an NFC/NFD pair (it renames the already-good file too) | 2 | 2 | 3 | 2 | NOT-DONE (harmless churn) |
| 11 | Reusable GitHub Action (`action.yml`) | 4 | 3 | 2 | 3 | NOT-DONE (needs a runner and a release) |
| 12 | `\\?\` long-path prefix on Windows disk walks | 3 | 2 | 3 | 4 | NOT-DONE (cannot test) |
| 13 | Per-line suppression / `.portacheckignore` | 3 | 3 | 4 | 3 | NOT-DONE |
| 14 | Full Unicode case folding option / NTFS `$MFT` names | 2 | 3 | 3 | 3 | NOT-DONE (no oracle) |
| 15 | Read nested submodules' `.gitmodules` | 2 | 3 | 4 | 3 | NOT-DONE |
| 16 | Real Windows/macOS run | 5 | 5 | n/a | 1 | NOT-DONE (needs a machine) |
| 17 | Trusted-publishing release workflow | 4 | 2 | 2 | 4 | NOT-DONE (Dan's decision) |
| 18 | Faster handling of one enormous name | 1 | 1 | 2 | 2 | NOT-DONE |
| 19 | Sparse-checkout awareness (ignore paths outside the cone) | 3 | 4 | 4 | 3 | NOT-DONE |
| 20 | `--only` as a settings-file key | 2 | 2 | 2 | 3 (a PR could hide findings) | NOT-DONE (deliberate) |
| 21 | Per-folder `--prefix-len` for monorepos cloned in different places | 2 | 3 | 3 | 2 | NOT-DONE |
| 22 | APFS / HFS+ name-length model (NFD unit count) | 2 | 3 | 3 | 3 | NOT-DONE (bytes limit already covers most) |
| 23 | CI step running `mypy` and the mutation script | 3 | 1 | 2 | 1 | NOT-DONE (CI not runnable here) |

## What could not be tested
Windows and macOS (still never run); the CI workflow; Python versions other than 3.13 this round; Git other than 2.43; installing from the real PyPI after release; whether the GitHub repository is public (the proxy returned 403), so the project URLs in the metadata are unverified.
