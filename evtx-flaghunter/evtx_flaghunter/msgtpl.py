# -*- coding: utf-8 -*-
"""Message-template rendering: reconstruct the Event Viewer 常规 body.

The General-tab text shown by Event Viewer = the provider's message
template (stored in its message DLL, e.g. ``adtschema.dll`` for the
Security channel) with ``%N`` placeholders filled by the record's
EventData values.  The templates are NOT inside the .evtx file, so this
module ships a pre-extracted cache (``data/msg_templates.json``, built by
``scripts/extract_msg_templates.py`` via ``FormatMessageW`` on a real
Windows box) and renders the body offline at runtime.

Offline fallback: when no template exists for ``(provider, eid)``, the
body is approximated as the EID's Chinese name plus the EventData pairs -
still far friendlier than raw XML for search and eyeballing.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from evtx_flaghunter.eid_dict import eid_name
from evtx_flaghunter.extract import parse_event_data

#: ``<Data Name="X">v</Data>`` and plain-tag payloads, in document order
#: (manifest events list Data elements in template-insert order).
_DATA_ORDERED_RE = re.compile(
    r'<Data\s+Name="([^"]+)"[^>]*>(.*?)</Data>', re.DOTALL | re.IGNORECASE
)
_EVENTDATA_RE = re.compile(r"<EventData[^>]*>(.*?)</EventData>", re.DOTALL)
_PLAIN_TAG_RE = re.compile(r"<([A-Za-z_][\w]*)>(.*?)</\1>", re.DOTALL)
_INSERT_RE = re.compile(r"%([0-9]{1,2})(?![0-9])")

_CACHE_PATH = Path(__file__).parent / "data" / "msg_templates.json"

_cache: dict[str, dict[str, str]] | None = None


def _load_cache() -> dict[str, dict[str, str]]:
    """Load the bundled template cache once (empty dict if missing)."""
    global _cache
    if _cache is None:
        try:
            raw = json.loads(_CACHE_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = {}
        _cache = {
            provider.lower(): {str(eid): tpl for eid, tpl in table.items()}
            for provider, table in raw.items()
        }
    return _cache


def providers() -> list[str]:
    """Provider names present in the bundled cache."""
    return list(_load_cache())


def template_for(provider: str, eid: str) -> str:
    """Look up the raw ``%N`` template for *provider* + *eid*."""
    table = _load_cache().get((provider or "").lower())
    if not table:
        return ""
    return table.get(str(eid), "")


def _ordered_values(xml: str) -> list[str]:
    """EventData values in document order (%N maps to the Nth value)."""
    values: list[str] = []
    for match in _DATA_ORDERED_RE.finditer(xml):
        values.append(match.group(2))
    if not values:
        for match in _EVENTDATA_RE.finditer(xml):
            for tag in _PLAIN_TAG_RE.finditer(match.group(1)):
                values.append(tag.group(2))
    return values


def fill_template(tpl: str, values: list[str]) -> str:
    """Replace ``%N`` inserts with *values* (missing values become ``-``)."""
    def sub(match: re.Match[str]) -> str:
        idx = int(match.group(1))
        if idx == 0:
            return "%0"
        return values[idx - 1] if idx <= len(values) else "-"

    filled = _INSERT_RE.sub(sub, tpl)
    return filled.replace("\r\n", "\n").strip()


def render_body(xml: str, provider: str, eid: str, channel: str = "") -> str:
    """Reconstruct the 常规 body for one record.

    Tries the provider template first; falls back to the Chinese EID name
    plus EventData pairs when the provider is unknown (e.g. Sysmon without
    an installed schema).  Returns "" when the record has no payload.
    """
    tpl = template_for(provider, eid)
    values = _ordered_values(xml)
    if tpl:
        return fill_template(tpl, values)
    fields = parse_event_data(xml)
    if not fields:
        return ""
    lines = [eid_name(eid, channel) or f"事件 {eid}"]
    for key, value in fields.items():
        if value:
            lines.append(f"{key}: {value}")
    return "\n".join(lines)


# -- cache building (used by scripts/extract_msg_templates.py) ----------------

_LOAD_FLAGS = 0x0002 | 0x0020  # LOAD_LIBRARY_AS_DATAFILE | AS_IMAGE_RESOURCE
_FM_FLAGS = 0x0100 | 0x0200 | 0x0800  # ALLOCATE_BUFFER | IGNORE_INSERTS | FROM_HMODULE
#: Templates keep their raw ``%N`` inserts (we fill them from EventData
#: ourselves), hence IGNORE_INSERTS - without it FormatMessage fails with
#: ERROR_INVALID_PARAMETER when no Arguments array is supplied.


def format_message(dll_path: str, msg_id: int) -> str:
    """Resolve one message from a message-table DLL via FormatMessageW.

    Uses the OS MUI selection, so on a zh-CN system this yields the same
    Chinese text Event Viewer displays.  Returns "" when *msg_id* is absent.
    """
    import ctypes
    import ctypes.wintypes as wt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LoadLibraryExW.restype = wt.HMODULE
    kernel32.LoadLibraryExW.argtypes = [wt.LPCWSTR, wt.HANDLE, wt.DWORD]
    kernel32.FormatMessageW.restype = wt.DWORD
    kernel32.FormatMessageW.argtypes = [
        wt.DWORD, wt.LPCVOID, wt.DWORD, wt.DWORD,
        ctypes.POINTER(wt.HMODULE), wt.DWORD, ctypes.POINTER(wt.LPVOID),
    ]
    kernel32.LocalFree.restype = wt.HMODULE
    kernel32.LocalFree.argtypes = [wt.HMODULE]

    hmod = kernel32.LoadLibraryExW(dll_path, None, _LOAD_FLAGS)
    if not hmod:
        raise OSError(f"LoadLibraryExW failed: {dll_path}")
    buf = wt.HMODULE()
    try:
        length = kernel32.FormatMessageW(
            _FM_FLAGS, hmod, msg_id, 0, ctypes.byref(buf), 0, None,
        )
        if not length:
            return ""
        text = ctypes.wstring_at(buf, length)
        return text.replace("\r\n", "\n").strip()
    finally:
        kernel32.LocalFree(buf)


def provider_event_map(provider: str) -> dict[int, int]:
    """``{event_id: message_id}`` from wevtutil metadata (needs the provider
    to be registered on the *building* machine; absent entries are skipped).
    """
    import subprocess
    from xml.etree import ElementTree

    proc = subprocess.run(
        ["wevtutil", "gp", provider, "/ge:true", "/f:xml"],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode or not proc.stdout.strip():
        return {}
    root = ElementTree.fromstring(proc.stdout)
    # Output is namespaced ({...}event) - match on the local name.
    result: dict[int, int] = {}
    for node in root.iter():
        if not node.tag.endswith("}event") and node.tag != "event":
            continue
        try:
            eid = int(node.get("value", ""))
            msg_id = int(node.get("message", ""))
        except ValueError:
            continue
        result.setdefault(eid, msg_id)
    return result


def extract_provider(provider: str, dll_path: str) -> dict[str, str]:
    """Extract ``{eid: template}`` for one provider from its message DLL."""
    table: dict[str, str] = {}
    for eid, msg_id in provider_event_map(provider).items():
        text = format_message(dll_path, msg_id)
        if text and "%" in text:
            table[str(eid)] = text
    return table


def save_cache(data: dict[str, dict[str, Any]], path: Path = _CACHE_PATH) -> None:
    """Persist the extracted cache (sorted for stable diffs)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    serial = {
        provider: {eid: table[eid] for eid in sorted(table, key=int)}
        for provider, table in sorted(data.items())
    }
    path.write_text(
        json.dumps(serial, ensure_ascii=False, indent=1), encoding="utf-8",
    )
    global _cache
    _cache = None  # force reload on next access
