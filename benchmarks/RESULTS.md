## Accuracy: 288 hostile cases, 2071 benign cases (seed 20261107)

| tool | precision | recall | F1 | false positives | missed |
|---|---|---|---|---|---|
| portacheck (this tree) | 1.000 | 1.000 | 1.000 | 0 | 0 |
| portacheck 0.2.0 | 1.000 | 0.882 | 0.937 | 0 | 34 |
| portacheck 0.3.0 @ round 2 | 1.000 | 0.965 | 0.982 | 0 | 10 |
| pre-commit regex (illegal names) | 1.000 | 0.493 | 0.660 | 0 | 146 |
| pre-commit case-conflict | 1.000 | 0.062 | 0.118 | 0 | 270 |
| git protectNTFS+HFS | 1.000 | 0.115 | 0.206 | 0 | 255 |

Recall by hazard class (caught / cases):

| hazard | portacheck (this tree) | portacheck 0.2.0 | portacheck 0.3.0 @ round 2 | pre-commit regex (illegal names) | pre-commit case-conflict | git protectNTFS+HFS |
|---|---|---|---|---|---|---|
| reserved name | 159/159 | 159/159 | 159/159 | 113/159 | 0/159 | 0/159 |
| invalid character | 11/11 | 11/11 | 11/11 | 11/11 | 0/11 | 0/11 |
| trailing dot/space | 12/12 | 12/12 | 12/12 | 6/12 | 0/12 | 0/12 |
| case collision | 18/18 | 18/18 | 18/18 | 0/18 | 18/18 | 0/18 |
| unicode (NFC/NFD) collision | 12/12 | 12/12 | 12/12 | 0/12 | 0/12 | 0/12 |
| component > 255 | 3/3 | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 |
| path > MAX_PATH | 6/6 | 6/6 | 6/6 | 0/6 | 0/6 | 0/6 |
| Git-dir alias (.git tricks) | 32/32 | 24/32 | 32/32 | 11/32 | 0/32 | 32/32 |
| Git-meta alias (.gitmodules...) | 8/8 | 2/8 | 8/8 | 1/8 | 0/8 | 0/8 |
| 8.3 short-name clash | 4/4 | 0/4 | 4/4 | 0/4 | 0/4 | 0/4 |
| risky symlink | 6/6 | 0/6 | 6/6 | 0/6 | 0/6 | 1/6 |
| invisible/bidi (Trojan Source) | 6/6 | 6/6 | 6/6 | 0/6 | 0/6 | 0/6 |
| name > 255 bytes (Linux NAME_MAX) | 3/3 | 1/3 | 1/3 | 0/3 | 0/3 | 0/3 |
| look-alike names | 8/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 |

## Git parity (ground truth = real git with core.protectNTFS/protectHFS): 3,000 random `.git`-synonym names

| git rejects & portacheck flags | portacheck only | git only | both clean |
|---|---|---|---|
| 319 | 0 | 0 | 2671 |

## .gitmodules (ground truth = `git fsck --strict`): 400 random files

| git complains & portacheck errors | portacheck only | git only | both clean |
|---|---|---|---|
| 332 | 0 | 0 | 68 |

(of the 68 both-clean files, 7 got a portacheck warning, e.g. the `ext::` transport, which Git's fsck does not check.)

## Robustness: one hostile path with 3,000 components (fresh process each)

| tool | seconds | peak RSS MB | exit |
|---|---|---|---|
| portacheck (this tree) | 0.07 | 23 | 0 |
| portacheck 0.3.0 @ round 2 | 9.17 | 25 | 0 |

## Speed: 500,000 tracked files, 33,310 folders (fresh process incl. start-up; median of 3; Python 3.13.18)

| tool | median s | best s | peak RSS MB |
|---|---|---|---|
| portacheck (this tree) | 9.17 | 7.68 | 251 |
| portacheck 0.3.0 @ round 2 | 9.03 | 8.98 | 251 |
| portacheck 0.2.0 | 27.44 | 26.41 | 405 |
| pre-commit regex (regex only, no Python start-up) | 20.24 | - | - |
| pre-commit case-conflict (set logic only) | 6.21 | - | - |

## Round 4 re-run (vs the round-3 tree; Linux, Git 2.43, Python 3.13, a quieter machine than the table above)

Accuracy unchanged: 1.000 / 1.000 / 1.000 on the 288 + 2,071 corpus; Git `.git`-synonym parity 319 / 0 / 0 / 2,671; `.gitmodules` vs `git fsck --strict` 332 / 0 / 0 / 68.

| 500,000 tracked files, median of 3 | median s | best s | peak RSS MB |
|---|---|---|---|
| round 4 tree | 4.15 | 2.90 | 250 |
| round 3 tree | 4.32 | 3.93 | 250 |

Hostile 3,000-component path: 0.11 s, 22 MB, both trees. The two trees differ by noise only: round 4 did not touch the scanning code.

## Round 5 re-run (vs the round-4 tree; Linux, Git 2.43, Python 3.13; the machine was shared with other jobs, so timings are noisy)

Accuracy unchanged: 1.000 / 1.000 / 1.000 on the 288 + 2,071 corpus; Git `.git`-synonym parity 319 / 0 / 0 / 2,671; `.gitmodules` vs `git fsck --strict` 332 / 0 / 0 / 68. Hostile 3,000-component path: 0.24 s, 23 MB for both trees. Peak memory for 500,000 files: 250 MB for both trees.

Speed is not a reliable comparison this round: the full 500,000-file benchmark gave a median of 15.5 s (best 8.9 s) for this tree and 13.2 s (best 9.4 s) for the previous one while other jobs ran; a second, in-process timing of `scan_paths` on 300,000 paths gave medians of 1.7 s and 1.6 s (this tree) against 2.0 s and 1.0 s (previous). The only new work on the hot path is one compiled-regex search per path, and only for `--git` / `--rev`. Not a measured regression, not a proven absence of one.
