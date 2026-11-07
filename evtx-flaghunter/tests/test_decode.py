"""Unit tests for evtx_flaghunter.decode (Base64/Hex/URL/ROT13 heuristics)."""

from __future__ import annotations

import base64

from evtx_flaghunter.decode import (
    auto_decode,
    decode_chain,
    parse_chain,
    try_base64,
    try_hex,
    try_url,
)
import pytest


def test_base64_flag_decoded():
    token = base64.b64encode(b"flag{abc}123456").decode()
    assert try_base64(token) == "flag{abc}123456"


def test_base64_utf16le_decoded():
    token = base64.b64encode("flag{宽字符}".encode("utf-16-le")).decode()
    assert try_base64(token) is not None
    assert "flag{" in try_base64(token)


def test_base64_rejects_binary():
    # Decodes to non-printable bytes -> must be rejected.
    assert try_base64(base64.b64encode(bytes(range(40))).decode()) is None


def test_base64_utf16le_garbage_rejected():
    # Wrong UTF-16LE decodings produce CJK garbage without ASCII runs
    # (regression: path fragments like "/TransitionsToOn" used to slip in).
    garbage = "㫽黚귈覊们ꞃ".encode("utf-16-le")
    assert try_base64(base64.b64encode(garbage).decode()) is None


def test_hex_contiguous():
    token = "flag{hex_test_01}".encode().hex()
    assert try_hex(token) == "flag{hex_test_01}"


def test_hex_spaced():
    token = " ".join(f"{b:02x}" for b in b"flag{spaced_hex}!")
    assert try_hex(token) == "flag{spaced_hex}!"


def test_url_decoding():
    assert try_url("flag%7Burl%7Dtest123") == "flag{url}test123"


def test_auto_decode_finds_nested_token():
    token = base64.b64encode(b"ctf{nested_token}").decode()
    text = f"cmd=echo {token} > out.txt"
    spans = auto_decode(text)
    assert spans and spans[0].codec == "base64"
    assert spans[0].text == "ctf{nested_token}"


def test_auto_decode_layer_limit():
    # Deeply chained encodings must not recurse forever.
    payload = b"flag{deep}" * 4
    text = payload.decode()
    for _ in range(10):
        text = base64.b64encode(text.encode()).decode()
    spans = auto_decode(text, max_layers=3)
    assert len(spans) <= 3


def test_decode_chain_explicit():
    inner = "flag{chain}"
    hexed = inner.encode().hex()
    spans = decode_chain(hexed, ["hex", "rot13"])
    assert spans[0].codec == "hex"
    assert spans[0].text == inner


def test_parse_chain_validates_names():
    assert parse_chain("b64,hex") == ["b64", "hex"]
    with pytest.raises(ValueError):
        parse_chain("b64,nope")
