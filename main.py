"""Application entrypoint for the All-In-One IT Configuration Tool PySide6 GUI."""
from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from services.privilege import ensure_admin
from ui.main_window import MainWindow


def main() -> int:
    if not ensure_admin():
        return 0
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
