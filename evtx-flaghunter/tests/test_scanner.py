"""Tests for scanner helpers: input expansion, presets and JSON->XML."""

from __future__ import annotations

import json
import zipfile

import pytest

from evtx_flaghunter.detect import FMT_EVTX, detect_file
from evtx_flaghunter.parser import json_to_xml
from evtx_flaghunter.presets import PRESETS, load_preset_file, resolve_patterns
from evtx_flaghunter.scanner import collect_files


def test_collect_files_expands_directory(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "a.evtx").write_bytes(b"ElfFile\x00")
    (tmp_path / "b.evtx").write_bytes(b"ElfFile\x00")
    files, temp = collect_files([str(tmp_path)])
    assert len(files) == 2 and temp == ""


def test_collect_files_extracts_zip(tmp_path):
    inner = tmp_path / "inner.evtx"
    inner.write_bytes(b"ElfFile\x00" + b"\x00" * 100)
    archive = tmp_path / "pack.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.write(inner, "inner.evtx")
    files, temp = collect_files([str(archive)])
    assert temp and len(files) == 1
    assert detect_file(files[0]).fmt == FMT_EVTX


def test_resolve_patterns_merges_and_dedups():
    keywords, regexes = resolve_patterns(
        "flag", ["flag{", "custom"], [], None
    )
    assert keywords.count("flag{") == 1
    assert "custom" in keywords
    assert regexes  # flag preset ships regex templates


def test_preset_file_parsing(tmp_path):
    preset = tmp_path / "preset.txt"
    preset.write_text("# comment\nflag{\nregex:flag\\{[^}]+\\}\n\n", "utf-8")
    keywords, regexes = load_preset_file(preset)
    assert keywords == ["flag{"]
    assert regexes == [r"flag\{[^}]+\}"]


def test_all_presets_define_patterns():
    for name, (keywords, regexes) in PRESETS.items():
        assert keywords or regexes, f"preset {name} is empty"


def test_json_to_xml_attributes_and_text():
    event = {
        "System": {
            "EventID": {"#attributes": {"Qualifiers": ""}, "#text": "4688"},
            "Provider": {"#attributes": {"Name": "SecAuditing"}},
            "Computer": "WIN-CTF01",
        }
    }
    xml = json_to_xml(event)
    assert '<EventID Qualifiers="">4688</EventID>' in xml
    assert '<Provider Name="SecAuditing"/>' in xml
    assert "<Computer>WIN-CTF01</Computer>" in xml


def test_json_to_xml_escapes_values():
    xml = json_to_xml({"Data": 'a<b & c"d'})
    assert "a&lt;b &amp; c&quot;d" in xml


def test_json_to_xml_list_children():
    event = {"EventData": {"Data": [
        {"#attributes": {"Name": "A"}, "#text": "1"},
        {"#attributes": {"Name": "B"}, "#text": "2"},
    ]}}
    xml = json_to_xml(event)
    assert xml.count("<Data ") == 2


def test_json_module_available():
    # The evtx crate binding must be importable for the parser to work.
    import evtx  # noqa: F401

    assert hasattr(evtx, "PyEvtxParser")


def test_scanner_module_imports():
    from evtx_flaghunter.model import ScanConfig
    from evtx_flaghunter.scanner import Scanner

    Scanner(ScanConfig())  # construction must not touch the filesystem
