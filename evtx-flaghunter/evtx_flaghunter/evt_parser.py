"""Legacy ``.evt`` (Windows XP / Server 2003) parser - EVT-Legacy submodule.

Implements design doc section 5.1 option B (pure-Python lightweight parser).
The ELF_OLD format is far simpler than BinXML: each record is a fixed header
followed by the source/computer name strings, the insertion strings, an
optional SID and user data. Records are parsed into the same
:class:`~evtx_flaghunter.parser.Record` shape as modern ``.evtx`` files so
matching and output layers are fully format-agnostic.

Record layout (little-endian, offsets relative to record start)::

    0x00  DWORD  magic (0x00002A2A -> bytes ``2a 2a 00 00``)
    0x04  DWORD  size (total record size, repeated at the tail)
    0x08  DWORD  record number
    0x0C  DWORD  time generated (POSIX seconds)
    0x10  DWORD  time written (POSIX seconds)
    0x14  DWORD  event identifier
    0x18  WORD   event type
    0x1A  WORD   number of strings
    0x1C  WORD   event category
    0x1E  WORD   reserved (0x0028 marker)
    0x20  DWORD  closing record number
    0x24  DWORD  string offset (relative to record start)
    0x28  DWORD  SID length
    0x2C  DWORD  SID offset
    0x30  DWORD  data length
    0x34  DWORD  data offset
    0x38  ...    source name (UTF-16LE, NUL-terminated)
    ...   ...    computer name (UTF-16LE, NUL-terminated)

A full ``.evt`` file starts with a 0x30-byte file header (magic ``LFLe`` at
offset 4); bare record dumps and damaged files are handled by resyncing on
the record magic.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from typing import Iterator
from xml.sax.saxutils import escape

from evtx_flaghunter.parser import Record

RECORD_MAGIC = 0x00002A2A
RECORD_MAGIC_BYTES = b"\x2a\x2a\x00\x00"
EVT_FILE_MAGIC = b"LFLe"
FIXED_HEADER_SIZE = 0x38
_MIN_RECORD_SIZE = 0x48  # fixed header + two names + minimal fields
_MAX_RECORD_SIZE = 0x100000  # 1 MiB guard against corrupt size fields

_UNPACK_FIXED = struct.Struct("<6I")  # magic..event_id
_UNPACK_WORDS = struct.Struct("<4H")  # type, strings, category, reserved
_UNPACK_TAIL = struct.Struct("<6I")  # closing..data_offset


def _iso_utc(posix_seconds: int) -> str:
    """Format POSIX seconds as ``YYYY-MM-DDTHH:MM:SSZ`` (matches evtx)."""
    try:
        stamp = datetime.fromtimestamp(posix_seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return ""
    return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_utf16z(data: bytes, offset: int) -> tuple[str, int]:
    """Read one NUL-terminated UTF-16LE string; return (text, next_offset)."""
    end = offset
    while end + 2 <= len(data):
        if data[end] == 0 and data[end + 1] == 0:
            return data[offset:end].decode("utf-16-le", errors="replace"), end + 2
        end += 2
    return data[offset:end].decode("utf-16-le", errors="replace"), len(data)


def _decode_user_data(blob: bytes) -> str:
    """Best-effort decode of the binary user-data blob for text matching.

    CTF flags hidden in legacy records may be stored as ASCII or UTF-16LE;
    both are surfaced as printable text, everything else becomes spaces.
    """
    if not blob:
        return ""
    # UTF-16LE ASCII text shows a NUL byte on every odd position.
    if len(blob) % 2 == 0 and blob.count(0) >= len(blob) // 4 and blob[1::2].count(0):
        text = blob.decode("utf-16-le", errors="replace")
    else:
        text = blob.decode("latin-1")
    return "".join(ch if ch.isprintable() else " " for ch in text).strip()


def parse_record(blob: bytes) -> Record | None:
    """Parse one raw ELF_OLD record into a :class:`Record` (or None)."""
    if len(blob) < _MIN_RECORD_SIZE:
        return None
    (_magic, size, record_number, t_gen, t_written, event_id) = (
        _UNPACK_FIXED.unpack_from(blob, 0)
    )
    ev_type, num_strings, _category, reserved = _UNPACK_WORDS.unpack_from(blob, 0x18)
    (_closing, string_offset, sid_len, _sid_off, data_len, data_off) = (
        _UNPACK_TAIL.unpack_from(blob, 0x20)
    )
    if reserved != 0x0028 or size != len(blob):
        return None  # not a structurally valid record

    try:
        source, pos = _read_utf16z(blob, FIXED_HEADER_SIZE)
        computer, _pos = _read_utf16z(blob, pos)
        strings: list[str] = []
        if 0 < string_offset <= len(blob):
            cursor = string_offset
            for _ in range(min(num_strings, 4096)):
                text, cursor = _read_utf16z(blob, cursor)
                strings.append(text)
    except struct.error:
        return None

    user_data = ""
    if 0 < data_len and 0 < data_off and data_off + data_len <= len(blob):
        user_data = _decode_user_data(blob[data_off:data_off + data_len])
    # The SID itself is not text; matching never needs it.

    parts = [f"EventRecordID={record_number}", f"Type={ev_type}"]
    if _category:
        parts.append(f"Category={_category}")
    event_data = "".join(
        f'<Data Name="String{i}">{escape(text)}</Data>'
        for i, text in enumerate(strings)
    )
    if user_data:
        event_data += f'<Data Name="EventData">{escape(user_data)}</Data>'
    xml = (
        "<Event><System>"
        f"<Provider Name=\"{escape(source)}\"/>"
        f"<EventID>{event_id}</EventID>"
        f"<TimeCreated SystemTime=\"{_iso_utc(t_written) or _iso_utc(t_gen)}\"/>"
        f"<Computer>{escape(computer)}</Computer>"
        f"<EventRecordID>{record_number}</EventRecordID>"
        f"<Keywords>{escape(' '.join(parts))}</Keywords>"
        "</System>"
        f"<EventData>{event_data}</EventData>"
        "</Event>"
    )
    return Record(record_number, _iso_utc(t_written) or _iso_utc(t_gen), xml)


def iter_evt_records(path: str) -> Iterator[Record]:
    """Yield :class:`Record` objects from a legacy ``.evt`` file.

    Corruption handling: when the reader hits bytes that do not form a valid
    record, it resyncs on the next record magic instead of failing (FR-9).
    The file is read into memory once; CTF-sized artifacts are well below
    the practical limit.
    """
    with open(path, "rb") as fh:
        data = fh.read()

    pos = 0
    if data[4:8] == EVT_FILE_MAGIC and len(data) >= 0x30:
        pos = struct.unpack_from("<I", data, 0)[0] or 0x30  # skip file header

    while pos + 8 <= len(data):
        magic, size = struct.unpack_from("<II", data, pos)
        valid = (
            magic == RECORD_MAGIC
            and _MIN_RECORD_SIZE <= size <= _MAX_RECORD_SIZE
            and pos + size <= len(data)
        )
        if not valid:
            nxt = data.find(RECORD_MAGIC_BYTES, pos + 1)
            if nxt == -1:
                break
            pos = nxt
            continue
        record = parse_record(data[pos:pos + size])
        if record is not None:
            yield record
        pos += size
