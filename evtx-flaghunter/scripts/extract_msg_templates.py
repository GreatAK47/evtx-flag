# -*- coding: utf-8 -*-
"""Extract message templates from the local Windows installation.

Resolves each provider's MessageFilePath (via PowerShell), pulls the
event->message-id map (via ``wevtutil gp /ge``), resolves the templates
through ``FormatMessageW`` (OS MUI language, e.g. zh-CN on a Chinese box)
and merges everything into ``evtx_flaghunter/data/msg_templates.json``.

Run on a real Windows machine once, ship the JSON with the tool.  Only
providers registered on the building machine can be extracted; the tool
falls back to EventData rendering for the rest.

Usage::

    python scripts/extract_msg_templates.py            # default set
    python scripts/extract_msg_templates.py P1 P2 ...  # custom providers
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evtx_flaghunter import msgtpl  # noqa: E402

#: Providers worth shipping for CTF-style incident response.
DEFAULT_PROVIDERS = (
    "Microsoft-Windows-Security-Auditing",
    "Microsoft-Windows-PowerShell",
    "Microsoft-Windows-Windows Firewall With Advanced Security",
    "Microsoft-Windows-Windows Defender",
    "Microsoft-Windows-TaskScheduler",
    "Microsoft-Windows-TerminalServices-LocalSessionManager",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
    "Microsoft-Windows-Kernel-PnP",
    "Microsoft-Windows-WMI-Activity",
    "Microsoft-Windows-Sysmon",
    "Microsoft-Windows-DriverFrameworks-UserMode",
    "Microsoft-Windows-Security-Mitigations",
)


def message_file_path(provider: str) -> str:
    """Resolve the provider's message DLL path via PowerShell."""
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         f'(Get-WinEvent -ListProvider "{provider}").MessageFilePath'],
        capture_output=True, text=True, check=False,
    )
    path = (proc.stdout or "").strip()
    if proc.returncode or not path:
        return ""
    return (
        path.replace("%SystemRoot%", r"C:\Windows")
        .replace("%windir%", r"C:\Windows")
    )


def main() -> None:
    providers = sys.argv[1:] or list(DEFAULT_PROVIDERS)
    merged: dict[str, dict[str, str]] = {}
    if Path(msgtpl._CACHE_PATH).exists():
        merged = dict(msgtpl._load_cache())
    for provider in providers:
        dll = message_file_path(provider)
        if not dll or not Path(dll).exists():
            print(f"[skip] {provider}: MessageFilePath 未注册 ({dll!r})")
            continue
        table = msgtpl.extract_provider(provider, dll)
        if not table:
            print(f"[skip] {provider}: 消息表为空或不含模板")
            continue
        merged.setdefault(provider, {}).update(table)
        print(f"[ok]   {provider}: {len(table)} 个模板 ({dll})")
    msgtpl.save_cache(merged)
    total = sum(len(t) for t in merged.values())
    print(f"总计 {len(merged)} 个 provider / {total} 个模板 -> {msgtpl._CACHE_PATH}")


if __name__ == "__main__":
    main()
