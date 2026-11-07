## Accuracy: 277 hostile cases, 2062 benign cases (seed 20261107)

| tool | precision | recall | F1 | false positives | missed |
|---|---|---|---|---|---|
| portacheck (this tree) | 1.000 | 1.000 | 1.000 | 0 | 0 |
| portacheck 0.2.0 | 1.000 | 0.913 | 0.955 | 0 | 24 |
| pre-commit regex (illegal names) | 1.000 | 0.513 | 0.678 | 0 | 135 |
| pre-commit case-conflict | 1.000 | 0.065 | 0.122 | 0 | 259 |
| git protectNTFS+HFS | 1.000 | 0.119 | 0.213 | 0 | 244 |

Recall by hazard class (caught / cases):

| hazard | portacheck (this tree) | portacheck 0.2.0 | pre-commit regex (illegal names) | pre-commit case-conflict | git protectNTFS+HFS |
|---|---|---|---|---|---|
| reserved name | 159/159 | 159/159 | 113/159 | 0/159 | 0/159 |
| invalid character | 11/11 | 11/11 | 11/11 | 0/11 | 0/11 |
| trailing dot/space | 12/12 | 12/12 | 6/12 | 0/12 | 0/12 |
| case collision | 18/18 | 18/18 | 0/18 | 18/18 | 0/18 |
| unicode (NFC/NFD) collision | 12/12 | 12/12 | 0/12 | 0/12 | 0/12 |
| component > 255 | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 |
| path > MAX_PATH | 6/6 | 6/6 | 0/6 | 0/6 | 0/6 |
| Git-dir alias (.git tricks) | 32/32 | 24/32 | 11/32 | 0/32 | 32/32 |
| Git-meta alias (.gitmodules...) | 8/8 | 2/8 | 1/8 | 0/8 | 0/8 |
| 8.3 short-name clash | 4/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| risky symlink | 6/6 | 0/6 | 0/6 | 0/6 | 1/6 |
| invisible/bidi (Trojan Source) | 6/6 | 6/6 | 0/6 | 0/6 | 0/6 |

## Git parity (ground truth = real git with core.protectNTFS/protectHFS): 3,000 random `.git`-synonym names

| git rejects & portacheck flags | portacheck only | git only | both clean |
|---|---|---|---|
| 319 | 0 | 0 | 2671 |

## Speed: 500,000 tracked files, 33,310 folders (fresh process incl. start-up; median of 5; Python 3.13.18)

| tool | median s | best s | peak RSS MB |
|---|---|---|---|
| portacheck (this tree) | 2.36 | 2.23 | 218 |
| portacheck 0.2.0 | 6.93 | 6.59 | 405 |
| pre-commit regex (regex only, no Python start-up) | 5.66 | - | - |
| pre-commit case-conflict (set logic only) | 1.93 | - | - |
