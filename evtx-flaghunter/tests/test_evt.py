"""Tests for the EVT-Legacy submodule (XP/2003 .evt parsing)."""

from __future__ import annotations

import struct

from evtx_flaghunter.detect import FMT_EVT, detect_file
from evtx_flaghunter.evt_parser import (
    EVT_FILE_MAGIC,
    iter_evt_records,
    parse_record,
)
from evtx_flaghunter.model import ScanConfig
from evtx_flaghunter.scanner import EV_DONE, EV_FILE_DONE, EV_HIT, Scanner

import pytest


def _make_record(
    record_number: int = 1,
    event_id: int = 4625,
    t_gen: int = 1600000000,
    t_written: int = 1600000100,
    source: str = "TestSrc",
    computer: str = "PC-01",
    strings: tuple[str, ...] = ("flag{evt_legacy}",),
    user_data: bytes = b"",
    ev_type: int = 0,
    category: int = 0,
) -> bytes:
    """Build one structurally valid ELF_OLD record blob."""
    src_b = source.encode("utf-16-le") + b"\x00\x00"
    cmp_b = computer.encode("utf-16-le") + b"\x00\x00"
    string_offset = 0x38 + len(src_b) + len(cmp_b)
    data_offset = string_offset + sum(
        len(s.encode("utf-16-le")) + 2 for s in strings
    )
    size = data_offset + len(user_data)
    blob = struct.pack(
        "<6I", 0x2A2A, size, record_number, t_gen, t_written, event_id
    )
    blob += struct.pack("<4H", ev_type, len(strings), category, 0x0028)
    blob += struct.pack(
        "<6I", 0, string_offset, 0, 0, len(user_data), data_offset
    )
    blob += src_b + cmp_b
    for text in strings:
        blob += text.encode("utf-16-le") + b"\x00\x00"
    blob += user_data
    assert len(blob) == size
    return blob


def _evt_file(records: list[bytes], with_header: bool = True) -> bytes:
    body = b"".join(records)
    if not with_header:
        return body
    header = struct.pack("<I", 0x30) + EVT_FILE_MAGIC + b"\x00" * 0x28
    return header + body


def test_parse_record_fields():
    record = parse_record(_make_record())
    assert record is not None
    assert record.event_id == "4625"
    assert record.provider == "TestSrc"
    assert record.computer == "PC-01"
    assert record.record_id == 1
    assert record.event_time.startswith("2020-09-")


def test_parse_record_strings_in_xml():
    record = parse_record(_make_record())
    assert record is not None
    assert "flag{evt_legacy}" in record.xml
    assert '<Data Name="String0">flag{evt_legacy}</Data>' in record.xml


def test_parse_record_ascii_user_data():
    record = parse_record(_make_record(user_data=b"user=bob action=logon"))
    assert record is not None
    assert "user=bob action=logon" in record.xml


def test_parse_record_utf16_user_data():
    blob = _make_record(user_data="flag{hidden_evt}".encode("utf-16-le"))
    record = parse_record(blob)
    assert record is not None
    assert "flag{hidden_evt}" in record.xml


def test_parse_record_rejects_bad_reserved():
    blob = bytearray(_make_record())
    blob[0x1E:0x20] = struct.pack("<H", 0x1234)
    assert parse_record(bytes(blob)) is None


def test_iter_skips_file_header():
    data = _evt_file([_make_record(record_number=1), _make_record(record_number=2)])
    records = list(iter_evt_records_bytes(data))
    assert len(records) == 2


def test_iter_resyncs_on_corruption():
    good = [_make_record(record_number=1), _make_record(record_number=2)]
    data = _evt_file(good[:1]) + b"garbage" * 10 + good[1]
    records = list(iter_evt_records_bytes(data))
    assert len(records) == 2
    assert records[1].record_id == 2


def test_detect_and_scan_e2e(tmp_path):
    data = _evt_file([_make_record(record_number=7)])
    path = tmp_path / "legacy.evt"
    path.write_bytes(data)
    assert detect_file(path).fmt == FMT_EVT

    events: list[tuple[str, object]] = []
    Scanner(ScanConfig(paths=[str(path)], preset="flag")).run(
        lambda event, payload: events.append((event, payload))
    )
    hits = [payload for event, payload in events if event == EV_HIT]
    assert len(hits) == 1
    assert hits[0].matched_keywords == ["flag{"]
    assert hits[0].provider == "TestSrc"
    assert "flag{evt_legacy}" in hits[0].content
    kinds = [event for event, _ in events]
    assert EV_DONE in kinds and EV_FILE_DONE in kinds


def iter_evt_records_bytes(data: bytes):  # pragma: no cover - test helper
    """Write *data* to a temp file and iterate records through the real API."""
    import tempfile
    from pathlib import Path

    with tempfile.NamedTemporaryFile(suffix=".evt", delete=False) as fh:
        fh.write(data)
        path = fh.name
    try:
        yield from iter_evt_records(path)
    finally:
        Path(path).unlink(missing_ok=True)


@pytest.mark.parametrize("count", [1, 3])
def test_iter_record_count(count: int) -> None:
    data = _evt_file([_make_record(record_number=i) for i in range(count)])
    assert len(list(iter_evt_records_bytes(data))) == count
