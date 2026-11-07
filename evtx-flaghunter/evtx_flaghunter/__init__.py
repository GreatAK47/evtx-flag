"""EVTX-FlagHunter: CTF-oriented Windows Event Log (.evtx) keyword hunter.

Public package exposing the core scanning API so the GUI, the CLI and
third-party scripts share one implementation.
"""

from evtx_flaghunter.model import RecordHit, ScanConfig
from evtx_flaghunter.scanner import Scanner

__version__ = "0.1.0"

__all__ = ["RecordHit", "ScanConfig", "Scanner", "__version__"]
