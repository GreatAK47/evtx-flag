"""``.evtx`` record parsing layer.

Wraps the ``evtx`` package (Rust kernel bindings, PyPI ``evtx``) which
streams records as JSON documents. Every record is converted to the standard
Windows Event XML form so output stays identical to ``evtx_dump -o xml``.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterator
from xml.sax.saxutils import escape

# JSON markers used by the evtx crate's serialization.
_ATTRS_KEY = "#attributes"
_TEXT_KEY = "#text"

# Lightweight field extractors over the generated XML.
_RE_EVENT_ID = re.compile(r"<EventID[^>]*>(\d+)</EventID>")
_RE_SYSTEM_TIME = re.compile(r'SystemTime="([^"]+)"')
_RE_CHANNEL = re.compile(r"<Channel>([^<]*)</Channel>")
_RE_COMPUTER = re.compile(r"<Computer>([^<]*)</Computer>")
_RE_PROVIDER = re.compile(r'<Provider Name="([^"]*)"')


class Record:
    """One parsed event record ready for matching."""

    __slots__ = (
        "file",
        "record_id",
        "timestamp",
        "xml",
        "event_id",
        "event_time",
        "channel",
        "provider",
        "computer",
    )

    def __init__(
        self,
        record_id: int,
        timestamp: str,
        xml: str,
        file: str = "",
    ) -> None:
        self.file = file
        self.record_id = record_id
        self.timestamp = timestamp
        self.xml = xml
        self.event_id = _first(_RE_EVENT_ID, xml)
        self.event_time = _first(_RE_SYSTEM_TIME, xml) or timestamp
        self.channel = _first(_RE_CHANNEL, xml)
        self.provider = _first(_RE_PROVIDER, xml)
        self.computer = _first(_RE_COMPUTER, xml)


def _first(pattern: re.Pattern[str], text: str) -> str:
    """Return group(1) of the first match or an empty string."""
    match = pattern.search(text)
    return match.group(1) if match else ""


def _attrs_to_str(attrs: dict[str, Any]) -> str:
    """Serialize a ``#attributes`` dict into XML attribute text."""
    return "".join(
        f' {key}="{escape(str(value), {chr(34): "&quot;"})}"'
        for key, value in attrs.items()
    )


def _node_to_xml(tag: str, value: Any) -> str:
    """Recursively convert one evtx-JSON node into an XML string."""
    if isinstance(value, (str, int, float)):
        text = escape(str(value), {chr(34): "&quot;"})
        return f"<{tag}>{text}</{tag}>"
    if isinstance(value, dict):
        attrs = value.get(_ATTRS_KEY, {})
        attr_str = _attrs_to_str(attrs) if isinstance(attrs, dict) else ""
        children = [
            key for key in value if key not in (_ATTRS_KEY, _TEXT_KEY)
        ]
        if not children:
            text = escape(str(value.get(_TEXT_KEY, "")))
            if not text:
                return f"<{tag}{attr_str}/>"
            return f"<{tag}{attr_str}>{text}</{tag}>"
        inner = "".join(
            _node_to_xml(key, value[key])
            if not isinstance(value[key], list)
            else "".join(_node_to_xml(key, item) for item in value[key])
            for key in children
        )
        return f"<{tag}{attr_str}>{inner}</{tag}>"
    return ""


def json_to_xml(event: dict[str, Any]) -> str:
    """Convert the evtx-JSON ``Event`` object into standard event XML."""
    return "".join(_node_to_xml(tag, value) for tag, value in event.items())


def iter_records(path: str) -> Iterator[Record]:
    """Yield :class:`Record` objects from one ``.evtx`` file.

    Corruption inside the file aborts iteration of *that file only*; the
    scanner reports the partial progress and moves on (design doc FR-9).
    """
    from evtx import PyEvtxParser  # imported lazily so tests stay light

    parser = PyEvtxParser(path)
    for record in parser.records_json():
        record_id = int(record.get("event_record_id", 0))
        timestamp = str(record.get("timestamp", ""))
        try:
            event = json.loads(record["data"]).get("Event", {})
        except (json.JSONDecodeError, KeyError, TypeError):
            # Unparseable payload: still surface the raw JSON for searching.
            event = {"Raw": str(record.get("data", ""))[:65536]}
        yield Record(record_id, timestamp, json_to_xml(event), file=path)
