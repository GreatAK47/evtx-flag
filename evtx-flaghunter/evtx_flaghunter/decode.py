"""Base64 / Hex / URL / ROT13 auto detection and decoding (design doc 7.2).

Decoding is heuristic and conservative: a token is only reported when it
decodes into mostly printable text, which keeps false positives low on real
event logs.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import urllib.parse

from evtx_flaghunter.model import DecodedSpan

# Minimum token lengths (design doc defaults).
MIN_B64_LEN = 8
MIN_HEX_LEN = 16
MAX_LAYERS = 5  # recursion guard against pathological chains

BASE64_RE = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")
SPACED_HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2} ){7,}[0-9a-fA-F]{2}\b")
URL_ESCAPED_RE = re.compile(r"%[0-9a-fA-F]{2}(?:%[0-9a-fA-F]{2}){3,}")

_PRINTABLE = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    " \t\r\n{}[]()<>+-*/=.:;,!?_@#$%^&~|\\'\"`"
)


def _printable_ratio(text: str) -> float:
    """Return the ratio of printable characters in *text* (empty -> 0.0)."""
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch in _PRINTABLE or ch.isprintable())
    return printable / len(text)


def _ascii_ratio(text: str) -> float:
    """Return the ratio of ASCII printable characters in *text*.

    Used for the UTF-16LE fallback: CJK-like garbage from wrong decodings
    is technically ``isprintable()``, so ASCII dominance is required there.
    """
    if not text:
        return 0.0
    good = sum(1 for ch in text if 0x20 <= ord(ch) <= 0x7E)
    return good / len(text)


def _utf16le_plausible(text: str) -> bool:
    """Heuristic validity check for a UTF-16LE decoded string.

    Wrong UTF-16LE decodings produce CJK-plane garbage with *zero* ASCII
    content. Legitimate payloads (e.g. Chinese CTF flags ``flag{宽字符}``)
    always keep an ASCII marker run such as ``flag``.
    """
    ratio = _ascii_ratio(text)
    if ratio >= 0.95:
        return True
    return ratio >= 0.25 and bool(re.search(r"[A-Za-z0-9]{4,}", text))


def _clean(text: str) -> str:
    """Strip control characters produced by noisy decodings."""
    return text.replace("\x00", "").strip()


def try_base64(token: str) -> str | None:
    """Decode a Base64 token; return ``None`` when not plausibly Base64."""
    token = token.strip()
    if len(token) < MIN_B64_LEN or len(token) % 4 != 0:
        return None
    try:
        raw = base64.b64decode(token, validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        try:
            # Windows frequently stores UTF-16LE payloads as Base64; apply
            # the plausibility heuristic to reject garbage decodings.
            text = _clean(base64.b64decode(token, validate=True).decode("utf-16-le"))
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return None
        if len(text) < 4 or not _utf16le_plausible(text):
            return None
    text = _clean(text)
    return text if len(text) >= 4 and _printable_ratio(text) >= 0.9 else None


def try_hex(token: str) -> str | None:
    """Decode a hex token (contiguous or space separated); printable only."""
    compact = token.replace(" ", "")
    if len(compact) < MIN_HEX_LEN or len(compact) % 2 != 0:
        return None
    try:
        raw = binascii.unhexlify(compact)
    except (binascii.Error, ValueError):
        return None
    for encoding in ("utf-8", "utf-16-le"):
        try:
            text = _clean(raw.decode(encoding))
        except UnicodeDecodeError:
            continue
        if len(text) < 4:
            continue
        if encoding == "utf-16-le" and not _utf16le_plausible(text):
            continue
        if _printable_ratio(text) >= 0.9:
            return text
    return None


def try_url(token: str) -> str | None:
    """Decode percent-encoded text; printable only."""
    try:
        text = _clean(urllib.parse.unquote(token))
    except Exception:  # noqa: BLE001 - unquote is total, guard anyway
        return None
    if text != token and len(text) >= 4 and _printable_ratio(text) >= 0.9:
        return text
    return None


def try_rot13(token: str) -> str | None:
    """Apply ROT13 (lossless, used via explicit decode chains)."""
    return codecs.decode(token, "rot13")


# Name -> (compiled candidate regex, decoder). Order matters: the first
# matching candidate wins for a given token span.
_CODECS: list[tuple[str, re.Pattern[str], object]] = [
    ("url", URL_ESCAPED_RE, try_url),
    ("base64", BASE64_RE, try_base64),
    ("hex", SPACED_HEX_RE, try_hex),
    ("hex", HEX_RE, try_hex),
]

CHAIN_DECODERS = {
    "b64": try_base64,
    "base64": try_base64,
    "hex": try_hex,
    "url": try_url,
    "rot13": try_rot13,
}


def parse_chain(chain: str | None) -> list[str]:
    """Parse a ``--decode-chain`` string like ``"b64,hex,rot13"``."""
    if not chain:
        return []
    names = [item.strip().lower() for item in chain.split(",") if item.strip()]
    unknown = [n for n in names if n not in CHAIN_DECODERS]
    if unknown:
        raise ValueError(f"unknown codec(s): {', '.join(unknown)}")
    return names


def decode_chain(token: str, chain: list[str]) -> list[DecodedSpan]:
    """Apply an explicit decoder chain, e.g. ``["hex", "base64"]``."""
    spans: list[DecodedSpan] = []
    current = token
    for depth, name in enumerate(chain, start=1):
        decoder = CHAIN_DECODERS[name]
        try:
            decoded = decoder(current)
        except Exception:  # noqa: BLE001 - user supplied chain must not crash
            decoded = None
        if not decoded:
            break
        spans.append(DecodedSpan(name, current, decoded, depth))
        current = decoded
    return spans


def auto_decode(
    text: str,
    max_layers: int = MAX_LAYERS,
    layer: int = 1,
) -> list[DecodedSpan]:
    """Scan *text* for encoded tokens and decode them recursively.

    Returns a flat list of :class:`DecodedSpan` ordered by discovery. Used
    both for the "nested" matching mode (decode before matching) and for the
    decoded-display lines attached to every hit.
    """
    if layer > max_layers:
        return []
    spans: list[DecodedSpan] = []
    seen: set[tuple[str, str]] = set()
    consumed: list[tuple[int, int]] = []

    for name, pattern, decoder in _CODECS:
        for match in pattern.finditer(text):
            start, end = match.start(), match.end()
            if any(s <= start < e or s < end <= e for s, e in consumed):
                continue
            token = match.group(0)
            key = (name, token)
            if key in seen:
                continue
            try:
                decoded = decoder(token)
            except Exception:  # noqa: BLE001 - never let one token break a scan
                decoded = None
            if not decoded:
                continue
            seen.add(key)
            consumed.append((start, end))
            spans.append(DecodedSpan(name, token, decoded, layer))
            spans.extend(auto_decode(decoded, max_layers, layer + 1))
    return spans
