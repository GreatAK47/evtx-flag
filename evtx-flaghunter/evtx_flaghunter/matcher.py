"""Keyword / regex matching engine (design doc section M2).

Exact mode uses an Aho-Corasick automaton (``pyahocorasick``) so that any
number of keywords cost one pass over the text; the module transparently
falls back to a plain ``str.find`` loop when the C extension is missing.
"""

from __future__ import annotations

import re

try:  # pragma: no cover - exercised implicitly by import order
    import ahocorasick  # type: ignore[import-untyped]

    _HAS_AC = True
except ImportError:  # pragma: no cover
    ahocorasick = None
    _HAS_AC = False


class Match:
    """One literal keyword occurrence inside a text."""

    __slots__ = ("keyword", "start", "end")

    def __init__(self, keyword: str, start: int, end: int) -> None:
        self.keyword = keyword
        self.start = start
        self.end = end

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"Match({self.keyword!r}, {self.start})"


class Matcher:
    """Multi-keyword (exact) + regex matcher.

    Args:
        keywords: Literal substrings to search for.
        regexes: Regular-expression patterns (fuzzy mode).
        ignore_case: Case-insensitive matching for both modes (default True,
            matching the GUI/CLI default of "CTF flags are sloppy about case").
    """

    def __init__(
        self,
        keywords: list[str],
        regexes: list[str],
        ignore_case: bool = True,
    ) -> None:
        self.keywords = list(dict.fromkeys(keywords))
        self.ignore_case = ignore_case
        flags = re.IGNORECASE if ignore_case else 0
        self.regexes: list[re.Pattern[str]] = []
        for pattern in regexes:
            try:
                self.regexes.append(re.compile(pattern, flags))
            except re.error as exc:
                raise ValueError(f"invalid regex {pattern!r}: {exc}") from exc
        self._ac = self._build_automaton() if _HAS_AC and self.keywords else None

    # -- construction ------------------------------------------------------

    def _build_automaton(self):  # type: ignore[no-untyped-def]
        """Build the Aho-Corasick automaton over (possibly folded) keywords."""
        automaton = ahocorasick.Automaton()  # type: ignore[union-attr]
        for keyword in self.keywords:
            key = keyword.lower() if self.ignore_case else keyword
            if key:
                automaton.add_word(key, keyword)
        automaton.make_automaton()
        return automaton

    # -- matching ----------------------------------------------------------

    def find(self, text: str) -> list[Match]:
        """Return every literal-keyword occurrence found in *text*."""
        if not text or not self.keywords:
            return []
        matches: list[Match] = []
        if self._ac is not None:
            haystack = text.lower() if self.ignore_case else text
            for end, keyword in self._ac.iter(haystack):
                matches.append(Match(keyword, end - len(keyword) + 1, end + 1))
        else:  # graceful fallback without the C extension
            for keyword in self.keywords:
                hay = text.lower() if self.ignore_case else text
                needle = keyword.lower() if self.ignore_case else keyword
                if not needle:
                    continue
                pos = hay.find(needle)
                while pos != -1:
                    matches.append(Match(keyword, pos, pos + len(needle)))
                    pos = hay.find(needle, pos + 1)
        matches.sort(key=lambda m: (m.start, m.keyword))
        return matches

    def find_regex(self, text: str) -> list[re.Match[str]]:
        """Return every regex match found in *text*."""
        if not text:
            return []
        found: list[re.Match[str]] = []
        for pattern in self.regexes:
            found.extend(pattern.finditer(text))
        found.sort(key=lambda m: m.start())
        return found

    def matched_keywords(self, text: str) -> list[str]:
        """Ordered, de-duplicated list of keywords hitting *text*."""
        names = [m.keyword for m in self.find(text)]
        return list(dict.fromkeys(names))

    @property
    def empty(self) -> bool:
        """True when neither keywords nor regexes were configured."""
        return not self.keywords and not self.regexes
