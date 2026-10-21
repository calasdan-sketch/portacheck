"""portacheck — find repo paths that break Windows checkouts before Windows does."""

from .rules import Finding, check_component, check_relpath
from .scan import case_collisions, scan_tree

__version__ = "0.1.0"
__all__ = ["scan_tree", "case_collisions", "check_component", "check_relpath", "Finding", "__version__"]
