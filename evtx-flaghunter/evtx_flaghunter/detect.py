"""File-format auto detection based on magic bytes (design doc section 4.3.2).

The file extension is treated as a hint only: CTF challenges frequently rename
or strip extensions, so identification always wins over the file name.
"""

from __future__ import annotations

import struct
from pathlib import Path

# Official Windows Event Log magics.
EVTX_FILE_MAGIC = b"ElfFile\x00"  # modern .evtx file header (offset 0)
EVTX_CHUNK_MAGIC = b"ElfChnk\x00"  # modern .evtx chunk header
EVT_RECORD_MAGIC = b"\x2a\x2a\x00\x00"  # legacy .evt record header (XP/2003)
EVT_FILE_MAGIC = b"LFLe"  # legacy .evt file header (offset 4)

_HEAD_SIZE = 4096

# Format badges shown in the GUI file list.
FMT_EVTX = "EVTX"
FMT_RECOVER = "RECOVER"
FMT_EVT = "EVT"
FMT_UNKNOWN = "UNKNOWN"


class DetectResult:
    """Outcome of probing one file.

    Attributes:
        fmt: One of the ``FMT_*`` constants.
        note: Extra human-readable hint (e.g. why a file is unsupported).
    """

    __slots__ = ("fmt", "note")

    def __init__(self, fmt: str, note: str = "") -> None:
        self.fmt = fmt
        self.note = note

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"DetectResult(fmt={self.fmt!r}, note={self.note!r})"


def _looks_like_legacy_evt(head: bytes) -> bool:
    """Structural check for the ELF_OLD record header of XP/2003 .evt.

    Layout: magic(4) size(4) record#(4) tgen(4) twr(4) eventid(4)
    type(2) numstrings(2) category(2) reserved(2)==0x0028 ...
    """
    if len(head) < 0x38:
        return False
    size = struct.unpack_from("<I", head, 4)[0]
    reserved = struct.unpack_from("<H", head, 0x1E)[0]
    return 0x48 <= size <= 0x100000 and reserved == 0x0028


def detect_file(path: str | Path) -> DetectResult:
    """Identify the log format of *path* by inspecting its leading bytes."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(_HEAD_SIZE)
    except OSError as exc:
        return DetectResult(FMT_UNKNOWN, f"unreadable: {exc}")

    if head.startswith(EVTX_FILE_MAGIC):
        return DetectResult(FMT_EVTX)
    if EVTX_CHUNK_MAGIC in head:
        # Damaged/truncated file header but intact chunks: recoverable evtx.
        return DetectResult(FMT_RECOVER, "file header damaged, chunk magic found")
    if head[4:8] == EVT_FILE_MAGIC:
        return DetectResult(FMT_EVT, "XP/2003 legacy format")
    if head.startswith(EVT_RECORD_MAGIC) and _looks_like_legacy_evt(head):
        return DetectResult(FMT_EVT, "XP/2003 legacy format (bare records)")
    return DetectResult(FMT_UNKNOWN, "no known event log magic")
