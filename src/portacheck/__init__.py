"""portacheck — find repo paths that break Windows checkouts before Windows does."""

from .rules import Finding, check_component, check_relpath, windows_fold
from .content import gitmodules_findings
from .scan import (case_collisions, git_entries, git_paths, git_snapshot, scan_paths, scan_tree, short_name_collisions,
                   unicode_collisions)

__version__ = "0.3.0"
__all__ = [
    "scan_tree", "scan_paths", "git_paths", "git_entries", "git_snapshot", "gitmodules_findings", "short_name_collisions", "case_collisions", "unicode_collisions",
    "check_component", "check_relpath", "windows_fold", "Finding", "__version__",
]
