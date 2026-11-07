"""Unit tests for evtx_flaghunter.detect (magic-based file identification)."""

from __future__ import annotations

import struct

from evtx_flaghunter.detect import (
    FMT_EVT,
    FMT_EVTX,
    FMT_RECOVER,
    FMT_UNKNOWN,
    detect_file,
)


def _make_file(tmp_path, name: str, data: bytes):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_detects_modern_evtx(tmp_path):
    path = _make_file(tmp_path, "a.evtx", b"ElfFile\x00" + b"\x00" * 4090)
    assert detect_file(path).fmt == FMT_EVTX


def test_detects_recoverable_evtx_by_chunk_magic(tmp_path):
    # Damaged file header but intact chunks -> recovery mode.
    data = b"\x00" * 100 + b"ElfChnk\x00" + b"\x00" * 4000
    path = _make_file(tmp_path, "b.bin", data)
    result = detect_file(path)
    assert result.fmt == FMT_RECOVER
    assert "chunk" in result.note


def test_detects_legacy_evt(tmp_path):
    # ELF_OLD record: magic, size, ..., reserved WORD 0x0028 at 0x1E.
    head = bytearray(b"\x00" * 0x40)
    head[0:4] = b"\x2a\x2a\x00\x00"
    head[4:8] = struct.pack("<I", 0x80)
    head[0x1E:0x20] = struct.pack("<H", 0x0028)
    path = _make_file(tmp_path, "old.evt", bytes(head) + b"\x00" * 128)
    assert detect_file(path).fmt == FMT_EVT


def test_detects_legacy_evt_with_file_header(tmp_path):
    # Full .evt file: 0x30-byte header with "LFLe" magic at offset 4.
    head = bytearray(b"\x00" * 0x30)
    head[0:4] = struct.pack("<I", 0x30)
    head[4:8] = b"LFLe"
    path = _make_file(tmp_path, "app.evt", bytes(head) + b"\x00" * 256)
    result = detect_file(path)
    assert result.fmt == FMT_EVT
    assert "XP/2003" in result.note


def test_unknown_file(tmp_path):
    path = _make_file(tmp_path, "c.txt", b"hello world" * 100)
    assert detect_file(path).fmt == FMT_UNKNOWN


def test_unreadable_file(tmp_path):
    assert detect_file(tmp_path / "missing.evtx").fmt == FMT_UNKNOWN


def test_renamed_extension_still_detected(tmp_path):
    # Extension is only a hint: magic bytes must win.
    path = _make_file(tmp_path, "flag.png", b"ElfFile\x00" + b"\x00" * 100)
    assert detect_file(path).fmt == FMT_EVTX
