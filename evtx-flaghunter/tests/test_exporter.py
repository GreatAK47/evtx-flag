"""Unit tests for evtx_flaghunter.exporter (JSON/JSONL/CSV output)."""

from __future__ import annotations

import csv
import json

from evtx_flaghunter.exporter import CSV_FIELDS, export, hit_to_dict
from evtx_flaghunter.model import DecodedSpan, RecordHit


def _sample_hit() -> RecordHit:
    return RecordHit(
        file="Security.evtx",
        record_id=142331,
        event_time="2026-10-12T03:14:15.926Z",
        event_id="4688",
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        computer="WIN-CTF01",
        matched_keywords=["flag{"],
        match_field="EventData",
        match_layer="plain",
        extracted="flag{evtx_1s_fun}",
        context="...echo flag{evtx_1s_fun}...",
        decoded=[DecodedSpan("base64", "ZmxhZw==", "flag", 1)],
        content="<Event>...</Event>",
    )


def test_json_export_roundtrip(tmp_path):
    path = tmp_path / "out.json"
    export([_sample_hit()], path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert len(data) == 1
    assert data[0]["event_id"] == "4688"
    assert data[0]["decoded"][0]["codec"] == "base64"
    assert data[0]["full_record_xml"] == "<Event>...</Event>"


def test_jsonl_export_line_count(tmp_path):
    path = tmp_path / "out.jsonl"
    export([_sample_hit(), _sample_hit()], path)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["record_id"] == 142331


def test_csv_export_columns(tmp_path):
    path = tmp_path / "out.csv"
    export([_sample_hit()], path)
    with open(path, encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 1
    assert rows[0]["extracted"] == "flag{evtx_1s_fun}"
    assert "base64" in rows[0]["decoded"]
    assert set(CSV_FIELDS) <= set(rows[0])


def test_explicit_format_override(tmp_path):
    path = tmp_path / "out.txt"
    export([_sample_hit()], path, fmt="json")
    assert json.loads(path.read_text(encoding="utf-8"))[0]["file"]


def test_unsupported_format_raises(tmp_path):
    import pytest

    with pytest.raises(ValueError):
        export([_sample_hit()], tmp_path / "out.xlsx")


def test_hit_to_dict_schema():
    data = hit_to_dict(_sample_hit())
    assert data["match_layer"] == "plain"
    assert data["matched_keywords"] == ["flag{"]
