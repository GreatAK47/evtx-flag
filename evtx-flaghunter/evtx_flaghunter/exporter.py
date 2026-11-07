"""Result exporters: JSON / JSONL / CSV (design doc section 7.4)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from evtx_flaghunter.model import RecordHit

#: Flat column order used by CSV export.
CSV_FIELDS = [
    "event_time",
    "event_id",
    "channel",
    "provider",
    "computer",
    "matched_keywords",
    "match_field",
    "match_layer",
    "extracted",
    "context",
    "decoded",
    "file",
    "record_id",
]


def hit_to_dict(hit: RecordHit) -> dict[str, object]:
    """Convert a hit into the JSON schema documented in the design doc."""
    return {
        "file": hit.file,
        "record_id": hit.record_id,
        "event_time": hit.event_time,
        "event_id": hit.event_id,
        "channel": hit.channel,
        "provider": hit.provider,
        "computer": hit.computer,
        "matched_keywords": hit.matched_keywords,
        "match_field": hit.match_field,
        "match_layer": hit.match_layer,
        "extracted": hit.extracted,
        "context": hit.context,
        "decoded": [
            {
                "codec": span.codec,
                "layer": span.layer,
                "source": span.source,
                "text": span.text,
            }
            for span in hit.decoded
        ],
        "full_record_xml": hit.content,
    }


def export_json(hits: list[RecordHit], path: str | Path) -> None:
    """Write all hits as one JSON array."""
    payload = [hit_to_dict(hit) for hit in hits]
    Path(path).write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def export_jsonl(hits: list[RecordHit], path: str | Path) -> None:
    """Write hits as newline-delimited JSON (stream friendly)."""
    with open(path, "w", encoding="utf-8") as fh:
        for hit in hits:
            fh.write(json.dumps(hit_to_dict(hit), ensure_ascii=False) + "\n")


def export_csv(hits: list[RecordHit], path: str | Path) -> None:
    """Write hits as flat CSV; multi-layer decodes are joined with ``; ``."""
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for hit in hits:
            row = {field: getattr(hit, field) for field in CSV_FIELDS}
            row["matched_keywords"] = ",".join(hit.matched_keywords)
            row["decoded"] = "; ".join(span.render() for span in hit.decoded)
            writer.writerow(row)


def export(hits: list[RecordHit], path: str | Path, fmt: str | None = None) -> Path:
    """Export *hits* to *path*, choosing the format from the suffix.

    Args:
        hits: Collected hits.
        path: Destination file path.
        fmt: Explicit format override (``json`` / ``jsonl`` / ``csv``).

    Raises:
        ValueError: If the format cannot be determined.
    """
    suffix = fmt or Path(path).suffix.lstrip(".").lower()
    if suffix in ("json", ""):
        export_json(hits, path)
    elif suffix == "jsonl":
        export_jsonl(hits, path)
    elif suffix == "csv":
        export_csv(hits, path)
    else:
        raise ValueError(f"unsupported export format: {suffix!r}")
    return Path(path)
