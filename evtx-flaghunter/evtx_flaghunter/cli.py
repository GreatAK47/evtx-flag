"""Command line interface - a thin mirror of the GUI (design doc 4.4)."""

from __future__ import annotations

import argparse
import sys

from evtx_flaghunter import __version__, exporter
from evtx_flaghunter.model import RecordHit, ScanConfig
from evtx_flaghunter.scanner import (
    EV_DONE,
    EV_ERROR,
    EV_FILE_DONE,
    EV_FILE_START,
    EV_HIT,
    EV_TOTAL,
    Scanner,
)


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser (mirrors design doc section 4.3)."""
    parser = argparse.ArgumentParser(
        prog="evtxflaghunt",
        description="EVTX-FlagHunter: search Windows event logs for CTF flags",
    )
    parser.add_argument("paths", nargs="*", help="evtx files / dirs / zips")
    parser.add_argument("-k", "--keyword", nargs="*", default=[], dest="keywords")
    parser.add_argument("-K", "--keywords-file", dest="preset_file")
    parser.add_argument("-r", "--regex", nargs="*", default=[], dest="regexes")
    parser.add_argument("-p", "--preset", default="flag",
                        help="flag|ctf|sqli|ps-enc|webshell|all")
    parser.add_argument("--exact-case", action="store_true",
                        help="case-sensitive matching")
    parser.add_argument("--nested", dest="nested", action="store_true",
                        default=True,
                        help="decode base64/hex before matching (default on)")
    parser.add_argument("--no-nested", dest="nested", action="store_false",
                        help="disable nested decode matching for speed")
    parser.add_argument("--no-decode", action="store_true",
                        help="disable auto-decode display")
    parser.add_argument("--decode-chain", default=None,
                        help="explicit chain, e.g. b64,hex,rot13")
    parser.add_argument("--extract", default=None,
                        help="custom extraction regex")
    parser.add_argument("--eid", nargs="*", default=[], help="event ID filter")
    parser.add_argument("--channel", nargs="*", default=[])
    parser.add_argument("--since", default="", help="RFC3339 lower bound")
    parser.add_argument("--until", default="", help="RFC3339 upper bound")
    parser.add_argument("--context", type=int, default=40)
    parser.add_argument("--top", type=int, default=0)
    parser.add_argument("--skip-broken", action="store_true")
    parser.add_argument("-o", "--output", default=None)
    parser.add_argument("--gui", action="store_true",
                        help="launch the GUI instead")
    parser.add_argument("-V", "--version", action="version",
                        version=f"evtx-flaghunter {__version__}")
    return parser


def _print_hit(hit: RecordHit, index: int) -> None:
    """Human-readable one-screen output for a single hit."""
    print("-" * 70)
    flag = f"  flag: {hit.extracted}" if hit.extracted else ""
    print(f"#{index}  {hit.event_time}  EID={hit.event_id}  "
          f"{hit.channel}  [{','.join(hit.matched_keywords)}]{flag}")
    print(f"    {hit.context}")
    for span in hit.decoded:
        print(f"    decoded: {span.render()}")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    args = build_arg_parser().parse_args(argv)
    if args.gui or not args.paths:
        from evtx_flaghunter.gui import run_gui

        run_gui()
        return 0

    config = ScanConfig(
        paths=args.paths,
        keywords=args.keywords,
        regex_patterns=args.regexes,
        preset=args.preset,
        preset_file=args.preset_file,
        ignore_case=not args.exact_case,
        extract=args.extract,
        nested=args.nested,
        auto_decode=not args.no_decode,
        decode_chain=args.decode_chain,
        context=args.context,
        top=args.top,
        eid_filter=args.eid,
        channel_filter=args.channel,
        since=args.since,
        until=args.until,
        skip_broken=args.skip_broken,
    )

    if config.decode_chain:
        from evtx_flaghunter.decode import parse_chain

        parse_chain(config.decode_chain)  # validate early

    hits: list[RecordHit] = []
    index = 0

    def emit(event: str, payload: object) -> None:
        nonlocal index
        if event == EV_TOTAL:
            print(f"scanning {payload} file(s)...")
        elif event == EV_FILE_START:
            entry = payload  # type: ignore[assignment]
            print(f"[+] {entry.path} ({entry.fmt})")
        elif event == EV_HIT:
            index += 1
            hits.append(payload)  # type: ignore[arg-type]
            _print_hit(payload, index)  # type: ignore[arg-type]
        elif event == EV_FILE_DONE:
            entry = payload  # type: ignore[assignment]
            status = entry.error or "ok"
            print(f"[=] {entry.path}: {entry.records} records, "
                  f"{entry.hits} hits ({status})")
        elif event == EV_ERROR:
            print(f"[!] {payload}", file=sys.stderr)
        elif event == EV_DONE:
            summary = payload  # type: ignore[assignment]
            print("=" * 70)
            print(f"done: {summary['files']} file(s), "
                  f"{summary['records']} records, {summary['hits']} hits")

    Scanner(config).run(emit)

    if args.output:
        out = exporter.export(hits, args.output)
        print(f"exported {len(hits)} hit(s) -> {out}")
    return 0 if hits or args.paths else 1


if __name__ == "__main__":
    raise SystemExit(main())
