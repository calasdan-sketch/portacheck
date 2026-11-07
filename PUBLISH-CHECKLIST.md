# Publish checklist (for Dan; nothing here has been run)

**Version to release: 0.3.0.** PyPI has only 0.1.0, so this is the first release since then (0.2.0 and 0.3.0 were never uploaded). It is not a break for anyone using only 0.1.0's plain scan, but `--strict` runs can see new warnings and an empty scan now exits 2; the changelog lists them. No version bump is needed, the files already say 0.3.0.

## Check first
1. Pull the branch into your own checkout and run `python -m pytest -q` (should end with all tests passed).
2. Push the branch, open a pull request, and wait for the GitHub CI to go green on Windows and Linux. This is the first time the Windows run will actually be seen.
3. Read `CHANGELOG.md` and the top of `README.md`. Change the install line comment ("PyPI still has 0.1.0") after the release.
4. Check on pypi.org that you own the project name `portacheck` and that your account has two-factor login on.

## Release commands (run in the repo root, in a clean folder)
```
python -m pip install build twine
python -m build
twine check dist/*
twine upload dist/*
git tag v0.3.0
git push origin v0.3.0
```
`twine upload` needs your PyPI login or an API token and cannot be undone for that version number. Uploading is free.

## After
- In a fresh virtual environment: `pip install portacheck`, then `portacheck --version` (should say 0.3.0) and `portacheck --git` inside any git folder.
- The pre-commit example in the README points at tag `v0.3.0`, which exists only after the `git tag` step.
