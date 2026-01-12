"""Path utilities for locating application directories."""
from __future__ import annotations

import sys
from pathlib import Path


def get_application_directory() -> Path:
    """
    Get the directory where the application is located.

    When running as a compiled .exe (PyInstaller), this returns the directory
    containing the .exe file.

    When running as a Python script, this returns the project root directory.

    Returns:
        Path to the application directory where files should be stored.
    """
    if getattr(sys, "frozen", False):
        # Running as compiled .exe (PyInstaller)
        # sys.executable points to the .exe file
        return Path(sys.executable).parent
    else:
        # Running as Python script
        # Go up from allinone_it_config/paths.py to project root
        return Path(__file__).parent.parent


def get_downloads_directory() -> Path:
    """Get the downloads directory for offline installers."""
    return get_application_directory() / "downloads"
