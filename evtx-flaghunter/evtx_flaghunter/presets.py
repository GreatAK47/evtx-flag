"""Built-in CTF keyword/regex presets (design doc section FR-2 / 4.2).

Each preset is a pair ``(keywords, regex_patterns)``. Presets are combined
with user supplied keywords, so a preset is a starting point, never a limit.
"""

from __future__ import annotations

from pathlib import Path

PRESETS: dict[str, tuple[list[str], list[str]]] = {
    "flag": (
        ["flag{", "ctf{"],
        [r"flag\{[^}\s]{1,200}\}", r"ctf\{[^}\s]{1,200}\}"],
    ),
    "ctf": (["ctf", "flag", "ctf{", "flag{"], []),
    "sqli": (
        ["union select", "information_schema", "or 1=1", "' or '"],
        [],
    ),
    "ps-enc": (
        ["-enc ", "-encodedcommand", "frombase64string"],
        [],
    ),
    "webshell": (
        ["eval(", "assert(", "system(", "passthru(", "cmd="],
        [],
    ),
    "all": (
        ["flag{", "ctf{", "union select", "-enc ", "mimikatz"],
        [r"flag\{[^}\s]{1,200}\}", r"ctf\{[^}\s]{1,200}\}"],
    ),
}


def load_preset_file(path: str | Path) -> tuple[list[str], list[str]]:
    """Read a user preset file (one pattern per line).

    Lines starting with ``regex:`` are treated as regular expressions,
    everything else is a literal keyword. Blank lines and ``#`` comments are
    ignored.
    """
    keywords: list[str] = []
    regexes: list[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("regex:"):
                regexes.append(line[6:].strip())
            else:
                keywords.append(line)
    return keywords, regexes


def resolve_patterns(
    preset: str,
    keywords: list[str],
    regexes: list[str],
    preset_file: str | None,
) -> tuple[list[str], list[str]]:
    """Merge preset, explicit keywords/regexes and an optional preset file."""
    p_keywords, p_regexes = PRESETS.get(preset, ([], []))
    all_keywords = list(p_keywords) + list(keywords)
    all_regexes = list(p_regexes) + list(regexes)
    if preset_file:
        f_keywords, f_regexes = load_preset_file(preset_file)
        all_keywords.extend(f_keywords)
        all_regexes.extend(f_regexes)
    # De-duplicate while keeping order.
    all_keywords = list(dict.fromkeys(all_keywords))
    all_regexes = list(dict.fromkeys(all_regexes))
    return all_keywords, all_regexes
