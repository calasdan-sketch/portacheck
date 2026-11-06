"""portacheck — find repo paths that break Windows checkouts before Windows does."""

from .rules import Finding, check_component, check_relpath, windows_fold
from .scan import case_collisions, git_paths, scan_paths, scan_tree, unicode_collisions

__version__ = "0.2.0"
__all__ = [
    "scan_tree", "scan_paths", "git_paths", "case_collisions", "unicode_collisions",
    "check_component", "check_relpath", "windows_fold", "Finding", "__version__",
]
