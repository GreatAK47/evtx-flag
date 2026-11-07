"""Unit tests for evtx_flaghunter.matcher (exact + regex modes)."""

from __future__ import annotations

import pytest

from evtx_flaghunter.matcher import Matcher


def test_exact_case_insensitive_default():
    matcher = Matcher(["flag{"], [])
    matches = matcher.find("cmd /c echo FLAG{abc}")
    assert matches and matches[0].keyword == "flag{"


def test_exact_case_sensitive():
    matcher = Matcher(["flag{"], [], ignore_case=False)
    assert matcher.find("FLAG{abc}") == []
    assert matcher.find("flag{abc}")


def test_multiple_keywords_single_pass():
    matcher = Matcher(["flag{", "ctf{"], [])
    matches = matcher.find("flag{a} ctf{b} flag{c}")
    assert len(matches) == 3


def test_matched_keywords_deduplicated_in_order():
    matcher = Matcher(["flag{", "ctf{"], [])
    assert matcher.matched_keywords("ctf{x} flag{y} ctf{z}") == ["ctf{", "flag{"]


def test_regex_mode():
    matcher = Matcher([], [r"flag\{[^}]+\}"])
    found = matcher.find_regex("noise flag{got_it} noise")
    assert found and found[0].group(0) == "flag{got_it}"


def test_regex_case_insensitive_flag_follows_config():
    assert Matcher([], [r"flag\{[^}]+\}"]).find_regex("FLAG{A}") != []
    strict = Matcher([], [r"flag\{[^}]+\}"], ignore_case=False)
    assert strict.find_regex("FLAG{A}") == []


def test_invalid_regex_raises_valueerror():
    with pytest.raises(ValueError):
        Matcher([], ["flag{[unclosed"])


def test_empty_matcher():
    matcher = Matcher([], [])
    assert matcher.empty
    assert matcher.find("flag{anything}") == []
