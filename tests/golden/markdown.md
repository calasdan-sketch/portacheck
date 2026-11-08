### portacheck: FAIL

7 error(s), 2 warning(s) in 11 path(s).

| severity | code | path | detail |
|---|---|---|---|
| error | `case_collision` | `src/Util.py` | paths differ only by case and cannot coexist on Windows: src/Util.py, src/util.py |
| error | `git_meta_alias` | `.GITMODULES` | '.GITMODULES' is a non-canonical spelling/alias of .gitmodules: on a case- or alias-insensitive filesystem Git reads it as the real file |
| error | `invalid_char` | `bad:name` | 'bad:name' contains character(s) Windows rejects: ':' |
| error | `invalid_char` | `gone/\u0007bell` | '\\u0007bell' contains character(s) Windows rejects: '\\u0007' |
| error | `reserved_name` | `docs/CON.md` | 'CON.md' collides with the Windows device name CON |
| error | `trailing_dot` | `trail.` | 'trail.' ends with a dot — Windows silently strips it |
| error | `unicode_collision` | `café.txt` | paths differ only by Unicode normalization and are the same file on macOS: 'cafe\\u0301.txt', 'caf\\u00e9.txt' |
| warn | `invisible_char` | `a\u202eb.txt` | 'a\\u202eb.txt' contains invisible/bidi format character(s) U+202E — the name can display differently from what it is |
| warn | `not_nfc` | `café.txt` | 'cafe\\u0301.txt' is not NFC-normalized (composed form: 'caf\\xe9.txt'); macOS and Linux tools can treat the two as different files |
