"""Core data models shared by every module.

All scan results are expressed through plain dataclasses so the GUI, CLI and
exporters operate on one identical structure (see design doc section 7.4).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DecodedSpan:
    """One successfully decoded encoded-token found inside a record.

    Attributes:
        codec: Codec identifier, e.g. ``base64`` / ``hex`` / ``url`` / ``rot13``.
        source: The original encoded token as it appeared in the record.
        text: Decoded, human-readable text.
        layer: Nesting depth (1 = first decoding pass).
    """

    codec: str
    source: str
    text: str
    layer: int = 1

    def render(self) -> str:
        """Return the single-line display form used by GUI and CLI output."""
        return f"[{self.codec}|L{self.layer}] {self.source} -> {self.text}"


@dataclass
class RecordHit:
    """A single log record that matched at least one search pattern."""

    file: str
    record_id: int
    event_time: str = ""
    event_id: str = ""
    channel: str = ""
    provider: str = ""
    computer: str = ""
    matched_keywords: list[str] = field(default_factory=list)
    match_field: str = "System"
    match_layer: str = "plain"  # "plain" | "decoded"
    extracted: str = ""
    context: str = ""
    decoded: list[DecodedSpan] = field(default_factory=list)
    content: str = ""
    # Quick-query enrichment (方向一/四): structured EventData fields, a
    # human-readable one-line conclusion and heuristic suspicion reasons.
    summary: str = ""
    fields: dict[str, str] = field(default_factory=dict)
    suspicious: list[str] = field(default_factory=list)


@dataclass
class ScanConfig:
    """Configuration for one scan run (mirrors GUI panel / CLI flags)."""

    paths: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    regex_patterns: list[str] = field(default_factory=list)
    preset: str = "flag"
    preset_file: str | None = None
    ignore_case: bool = True
    extract: str | None = None
    nested: bool = True  # on by default: encoded flags cannot be predicted
    auto_decode: bool = True
    decode_chain: str | None = None
    context: int = 40
    top: int = 0  # 0 = unlimited
    eid_filter: list[str] = field(default_factory=list)
    eid_match: bool = False  # True = EID filter is the match itself (quick queries)
    channel_filter: list[str] = field(default_factory=list)
    #: Hostname filter (bare-name tolerant, e.g. "lemon-squeezer" matches
    #: "lemon-squeezer.art.local"); empty = no host restriction.
    computer: str = ""
    since: str = ""
    until: str = ""
    skip_broken: bool = False


@dataclass
class FileEntry:
    """Per-file scan statistics shown in the GUI file list."""

    path: str
    fmt: str = "?"  # EVTX / RECOVER / EVT / UNKNOWN
    note: str = ""
    size: int = 0
    records: int = 0
    hits: int = 0
    error: str = ""
