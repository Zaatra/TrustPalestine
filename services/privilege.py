"""Admin privilege helpers for Windows."""
from __future__ import annotations

import ctypes
import sys


_MB_OK = 0x00000000
_MB_ICONWARNING = 0x00000030


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except AttributeError:
        return False


def relaunch_as_admin() -> bool:
    if not sys.platform.startswith("win"):
        return False
    if getattr(sys, "frozen", False):
        executable = sys.executable
        params = " ".join(f'"{arg}"' for arg in sys.argv[1:])
    else:
        executable = sys.executable
        params = " ".join(f'"{arg}"' for arg in sys.argv)
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, params, None, 1)
    return result > 32


def _show_admin_required_dialog() -> None:
    if not sys.platform.startswith("win"):
        return
    try:
        ctypes.windll.user32.MessageBoxW(
            None,
            "Administrator privileges are required to run this application.",
            "Administrator Required",
            _MB_OK | _MB_ICONWARNING,
        )
    except Exception:
        pass


def ensure_admin() -> bool:
    if not sys.platform.startswith("win"):
        return True
    if is_admin():
        return True
    _show_admin_required_dialog()
    relaunch_as_admin()
    return False
