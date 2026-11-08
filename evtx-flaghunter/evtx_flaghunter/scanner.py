"""Scan orchestration (design doc: 检索编排层 / M3 / M4).

The scanner expands the input paths (files, directories, zip archives),
routes every file through the format detector, streams records through the
matcher and emits progress/hit events. It is UI-agnostic: the GUI consumes
the event stream from a worker thread, the CLI prints it directly.
"""

from __future__ import annotations

import queue
import re
import shutil
import tempfile
import threading
import zipfile
from collections import Counter
from pathlib import Path
from typing import Callable

from evtx_flaghunter import decode as dec
from evtx_flaghunter.detect import (
    FMT_EVT,
    FMT_UNKNOWN,
    detect_file,
)
from evtx_flaghunter.evt_parser import iter_evt_records
from evtx_flaghunter.extract import (
    _account,
    enrich_hit as quick_enrich,
    get_field,
    parse_event_data,
)
from evtx_flaghunter.matcher import Matcher
from evtx_flaghunter.model import FileEntry, RecordHit, ScanConfig
from evtx_flaghunter.parser import Record, iter_records
from evtx_flaghunter.presets import resolve_patterns

#: Event IDs carrying user SID/name pairs used to build the SID map.
_SID_SOURCE_EIDS = {
    "4624", "4625", "4648", "4688", "4720", "4722", "4724", "4726",
    "4728", "4732", "4740", "4756",
}

EmitFn = Callable[[str, object], None]

#: Event names emitted during a scan (consumed by GUI / CLI).
EV_TOTAL = "total_files"
EV_FILE_START = "file_start"
EV_FILE_PROGRESS = "file_progress"
EV_HIT = "hit"
EV_FILE_DONE = "file_done"
EV_DONE = "done"
EV_ERROR = "error"

_PROGRESS_EVERY = 2000  # records between progress events


def collect_files(paths: list[str]) -> tuple[list[Path], str]:
    """Expand user input into a concrete list of candidate log files.

    Directories are walked recursively. Zip archives (common CTF packaging)
    are extracted into a temporary directory; the caller removes it via the
    returned cleanup token.

    Returns:
        ``(files, temp_dir)`` where ``temp_dir`` may be ``""`` when nothing
        was extracted.
    """
    files: list[Path] = []
    temp_dir = ""
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files.extend(p for p in sorted(path.rglob("*")) if p.is_file())
        elif path.suffix.lower() == ".zip" and path.is_file():
            if not temp_dir:
                temp_dir = tempfile.mkdtemp(prefix="evtxfh_")
            try:
                with zipfile.ZipFile(path) as zf:
                    zf.extractall(temp_dir)
                files.extend(sorted(Path(temp_dir).rglob("*")))
            except (zipfile.BadZipFile, OSError):
                files.append(path)  # let the detector report the problem
        elif path.is_file():
            files.append(path)
    return files, temp_dir


def _context_snippet(text: str, pos: int, width: int) -> str:
    """Return a window of ``width`` characters around *pos*."""
    start = max(0, pos - width)
    end = min(len(text), pos + width)
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    return prefix + text[start:end] + suffix


def _first_eventdata_pos(xml: str) -> int:
    """Index of the EventData section, or len(xml) when absent."""
    idx = xml.find("<EventData")
    return idx if idx != -1 else len(xml)


def _match_position(matcher: Matcher, xml: str) -> int:
    """Best-effort offset of the first plain match inside *xml*."""
    matches = matcher.find(xml)
    if matches:
        return matches[0].start
    regex_matches = matcher.find_regex(xml)
    return regex_matches[0].start() if regex_matches else 0


class Scanner:
    """Runs one scan configuration and emits progress/hit events."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._temp_dir = ""
        # SID -> DOMAIN\user map built while scanning (quick-query mode only).
        self.sid_map: dict[str, str] = {}
        # Event-ID frequency profile for every parsed record (quick mode).
        self.eid_counts: Counter[str] = Counter()
        # Computer names from the full event stream (quick mode), so the
        # GUI smart search can recognize hostnames that produced no hits.
        self.hosts: set[str] = set()

    def _collect_sid(self, xml: str) -> None:
        """Record user SID/name pairs from logon & account events."""
        fields = parse_event_data(xml)
        for sid_field, name_field in (
            ("TargetUserSid", "TargetUserName"),
            ("SubjectUserSid", "SubjectUserName"),
        ):
            sid = get_field(fields, sid_field)
            if sid:
                name = _account(fields, name_field)
                if name and name not in {"(空)", "-"}:
                    self.sid_map[sid] = name

    # -- public API --------------------------------------------------------

    def run(self, emit: EmitFn) -> None:
        """Blocking scan; report every event through *emit*."""
        keywords, regexes = resolve_patterns(
            self.config.preset,
            self.config.keywords,
            self.config.regex_patterns,
            self.config.preset_file,
        )
        matcher = Matcher(keywords, regexes, self.config.ignore_case)
        try:
            self._run_files(matcher, emit)
        finally:
            if self._temp_dir:
                shutil.rmtree(self._temp_dir, ignore_errors=True)
                self._temp_dir = ""

    def start_async(self) -> tuple["queue.Queue[tuple[str, object]]", threading.Thread]:
        """Start the scan on a daemon thread; return ``(queue, thread)``.

        Note: the emit callback must adapt the two-argument ``emit(event,
        payload)`` interface to a single queued item; passing ``queue.put``
        directly would turn *payload* into the ``block`` argument and the
        GUI would silently lose every event.
        """
        events: "queue.Queue[tuple[str, object]]" = queue.Queue()

        def emit(event: str, payload: object) -> None:
            events.put((event, payload))

        thread = threading.Thread(target=self._safe_run, args=(emit,), daemon=True)
        thread.start()
        return events, thread

    # -- internals ---------------------------------------------------------

    def _safe_run(self, emit: EmitFn) -> None:
        """Wrapper that converts unexpected crashes into an error event."""
        try:
            self.run(emit)
        except Exception as exc:  # noqa: BLE001 - report to UI, never die silently
            emit(EV_ERROR, f"scan aborted: {exc}")

    def _run_files(self, matcher: Matcher, emit: EmitFn) -> None:
        files, self._temp_dir = collect_files(self.config.paths)
        emit(EV_TOTAL, len(files))
        summary = {"files": 0, "records": 0, "hits": 0}

        for path in files:
            entry = FileEntry(
                path=str(path),
                size=path.stat().st_size if path.exists() else 0,
            )
            detected = detect_file(path)
            entry.fmt = detected.fmt
            entry.note = detected.note

            if detected.fmt == FMT_UNKNOWN:
                entry.error = detected.note or "unsupported format"
                summary["files"] += 1
                emit(EV_FILE_DONE, entry)
                continue

            emit(EV_FILE_START, entry)
            try:
                self._scan_one_file(path, entry, matcher, emit, summary)
            except Exception as exc:  # noqa: BLE001 - partial results still count
                entry.error = f"parse stopped: {exc}"
                if not self.config.skip_broken:
                    emit(EV_ERROR, f"{path.name}: {entry.error}")
            summary["files"] += 1
            emit(EV_FILE_DONE, entry)

        emit(EV_DONE, summary)

    def _scan_one_file(
        self,
        path: Path,
        entry: FileEntry,
        matcher: Matcher,
        emit: EmitFn,
        summary: dict[str, int],
    ) -> None:
        """Stream one file through the matcher (design doc M1 -> M2)."""
        display = str(path)
        # Format-aware record source: modern .evtx via the Rust kernel
        # binding, legacy XP/2003 .evt via the EVT-Legacy submodule.
        if entry.fmt == FMT_EVT:
            records = iter_evt_records(display)
        else:
            records = iter_records(display)
        for record in records:
            entry.records += 1
            summary["records"] += 1
            if entry.records % _PROGRESS_EVERY == 0:
                emit(EV_FILE_PROGRESS, entry)

            if self.config.top and entry.hits >= self.config.top:
                break
            # Profile semantics: the histogram counts every record inside
            # the time range regardless of the EID filter, so it reflects
            # the whole-file landscape even for a single-scenario query.
            # SID sources are likewise collected before the EID filter so
            # e.g. a firewall-only query can still resolve ModifyingUser
            # SIDs from 4624/4688 records (P1: SID -> account mapping).
            if self.config.eid_match:
                # Host inventory from the full stream: a hostname must be
                # recognizable even when none of its records matched.
                if record.computer:
                    self.hosts.add(record.computer)
                if (
                    not self.config.computer
                    or self._host_matches(record.computer)
                ) and self._in_time_range(record):
                    self.eid_counts[record.event_id] += 1
                if record.event_id in _SID_SOURCE_EIDS:
                    self._collect_sid(record.xml)
            if not self._pass_filters(record):
                continue

            hit = self._match_record(record, matcher)
            if hit is not None:
                entry.hits += 1
                summary["hits"] += 1
                emit(EV_HIT, hit)

    def _in_time_range(self, record: Record) -> bool:
        """True when the record falls inside the configured since/until."""
        config = self.config
        stamp = record.event_time
        if config.since and stamp < config.since:
            return False
        if config.until and stamp > config.until:
            return False
        return True

    def _host_matches(self, value: str) -> bool:
        """Bare-name host match (FQDN-suffix tolerant).

        ``lemon-squeezer`` in the config matches record computer
        ``lemon-squeezer.art.local`` and vice versa, because CTF answers
        use either form interchangeably.
        """
        needle = (self.config.computer or "").split(".")[0].lower()
        bare = (value or "").split(".")[0].lower()
        return bool(needle) and bare == needle

    def _pass_filters(self, record: Record) -> bool:
        """Event ID / channel / host / time-range pre-filters (FR-5)."""
        config = self.config
        if config.computer and not self._host_matches(record.computer):
            return False
        if config.eid_filter and record.event_id not in config.eid_filter:
            return False
        if config.channel_filter and record.channel not in config.channel_filter:
            return False
        return self._in_time_range(record)

    def _match_record(self, record: Record, matcher: Matcher) -> RecordHit | None:
        """Match one record; returns None when nothing matches."""
        config = self.config
        xml = record.xml

        if config.eid_match:
            # Quick-query mode: the event ID filter IS the match criterion,
            # so every pre-filtered record is emitted as a hit.
            pos = _first_eventdata_pos(xml)
            hit = self._build_hit(
                record, matcher, [f"eid:{record.event_id}"], "plain", [],
                pos=pos,
            )
            # 方向一/四: structured fields + conclusion + suspicion reasons.
            quick_enrich(hit)
            return hit

        keywords = matcher.matched_keywords(xml)
        regex_hits = matcher.find_regex(xml)
        decoded_spans: list[dec.DecodedSpan] = []

        if keywords or regex_hits:
            if config.auto_decode:
                pos = _match_position(matcher, xml)
                decoded_spans = dec.auto_decode(
                    _context_snippet(xml, pos, max(config.context, 200))
                )
            return self._build_hit(
                record, matcher, keywords, "plain", decoded_spans
            )

        if config.nested:
            # Decode-first matching: hidden flags inside encoded payloads.
            for span in dec.auto_decode(xml):
                span_keywords = matcher.matched_keywords(span.text)
                span_regex = matcher.find_regex(span.text)
                if span_keywords or span_regex:
                    merged = list(dict.fromkeys(keywords + span_keywords))
                    return self._build_hit(
                        record, matcher, merged, "decoded", [span]
                    )
        return None

    def _build_hit(
        self,
        record: Record,
        matcher: Matcher,
        keywords: list[str],
        layer: str,
        decoded_spans: list[dec.DecodedSpan],
        pos: int | None = None,
    ) -> RecordHit:
        """Assemble a :class:`RecordHit` from a matching record.

        ``pos`` optionally overrides the auto-detected match offset (used by
        quick-query mode to point the context at the EventData section).
        """
        config = self.config
        xml = record.xml
        if pos is None:
            pos = _match_position(matcher, xml)
        context = _context_snippet(xml, pos, config.context)

        extracted = ""
        if config.extract:
            try:
                pattern = re.compile(config.extract, re.IGNORECASE)
            except re.error:
                pattern = None
            if pattern:
                match = pattern.search(xml)
                if not match:  # also look inside decoded layers
                    for span in decoded_spans:
                        match = pattern.search(span.text)
                        if match:
                            break
                if match:
                    extracted = match.group(0)

        return RecordHit(
            file=record.file,
            record_id=record.record_id,
            event_time=record.event_time,
            event_id=record.event_id,
            channel=record.channel,
            provider=record.provider,
            computer=record.computer,
            matched_keywords=keywords,
            match_field=(
                "EventData" if pos >= _first_eventdata_pos(xml) else "System"
            ),
            match_layer=layer,
            extracted=extracted,
            context=context,
            decoded=decoded_spans,
            content=xml,
        )
