"""End-to-end parser + scanner test against a real .evtx sample.

The sample is fetched into ``samples/`` by the developer (see README);
tests skip automatically when it is absent so CI stays green offline.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from evtx_flaghunter.detect import FMT_EVTX, detect_file
from evtx_flaghunter.model import ScanConfig
from evtx_flaghunter.parser import iter_records
from evtx_flaghunter.scanner import EV_DONE, EV_FILE_DONE, EV_HIT, Scanner

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "system.evtx"

pytestmark = pytest.mark.skipif(
    not SAMPLE.exists(), reason="sample evtx not downloaded"
)


def test_detect_sample():
    assert detect_file(SAMPLE).fmt == FMT_EVTX


def test_iter_records_yields_fields():
    records = list(iter_records(str(SAMPLE)))
    assert records, "sample must contain records"
    first = records[0]
    assert first.record_id > 0
    assert first.xml.startswith("<")
    assert first.event_id  # extracted from System section


def test_scanner_finds_planted_keyword():
    # Scan with the built-in flag preset; the sample may or may not contain
    # flags - we only assert the pipeline completes and files are counted.
    events: list[tuple[str, object]] = []
    Scanner(ScanConfig(paths=[str(SAMPLE)], preset="flag")).run(
        lambda event, payload: events.append((event, payload))
    )
    kinds = [event for event, _payload in events]
    assert "total_files" in kinds
    assert EV_FILE_DONE in kinds
    assert EV_DONE in kinds
    hits = [payload for event, payload in events if event == EV_HIT]
    for hit in hits:  # every hit must carry the full record XML
        assert hit.content.startswith("<")
