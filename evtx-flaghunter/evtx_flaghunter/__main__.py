"""``python -m evtx_flaghunter`` entry point.

GUI is the default (design doc: GUI-first); use ``--cli`` for the terminal.
"""

from __future__ import annotations

import sys


def main() -> int:
    """Dispatch to GUI or CLI depending on the first argument."""
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        from evtx_flaghunter.cli import main as cli_main

        return cli_main(sys.argv[2:])
    from evtx_flaghunter.gui import run_gui

    run_gui()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
