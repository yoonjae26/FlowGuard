"""Payload normalization and decoding.

The taint registry compares known-sensitive values against *text*. An agent
that wants to leak a value will not send it verbatim, so before matching we
expand the outbound text into candidate variants: the normalized text plus
whatever we can obtain by undoing common reversible obfuscations (base64,
hex, URL/HTML/unicode escapes, rot13, reversal, ...), recursively up to a
small depth. Each variant carries the decoder chain that produced it
("base64>url") so audit logs can explain why a match fired.

This is deliberately a fixed catalogue, not a general solver: ciphers with a
secret key, paraphrase and steganography are out of reach (see docs/THREAT_MODEL.md).
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
from collections.abc import Callable
from urllib.parse import unquote, unquote_plus

_ZERO_WIDTH = {ord(c): None for c in "\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\ufeff\u00ad"}
_SEPARATORS = re.compile(r"[\s\-_.,:;/\\|]+")
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{6,}={0,2}")
_B64_TOKEN_WS = re.compile(r"[A-Za-z0-9+/_=\s-]{10,}")  # base64.b64decode ignores embedded whitespace
_B32_TOKEN = re.compile(r"[A-Za-z2-7]{8,}={0,6}")
_HEX_TOKEN = re.compile(r"(?:[0-9a-fA-F]{2}){4,}")
_HEX_TOKEN_WS = re.compile(r"[0-9a-fA-F\s]{10,}")  # bytes.fromhex ignores embedded whitespace
_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
_CHARCODES = re.compile(r"(?:\b\d{2,3}\b[\s,;]+){3,}\b\d{2,3}\b")

_MAX_CHILD_FACTOR = 4  # decoded output is capped relative to its input

# Salvage of damaged encodings. Models retype long base64/hex imperfectly (dropping,
# repeating or inserting characters), which shifts alignment for everything after the
# damage. Requiring the whole decoding to look like text would then discard a perfectly
# readable tail, so for long tokens we also keep the readable runs inside the decoding.
_MIN_SALVAGE_TOKEN = 24
_MIN_RUN = 6
_MIN_SALVAGED_CHARS = 12
_MIN_SALVAGED_SHARE = 0.2  # readable runs must be a real part of the decoding, not chance
_MAX_SALVAGED_RUNS = 64
_READABLE_RUN = re.compile("[ -~\\t\\r\\n]{" + str(_MIN_RUN) + ",}")  # ASCII only: noise often forms valid UTF-8


def normalize(text: str) -> str:
    """NFKC-fold (fullwidth digits, ligatures, ...) and drop zero-width characters."""
    return unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)


def compact(text: str) -> str:
    """Remove separators and case so '123-45-6791' and '1 2 3 4 5 6 7 9 1' compare equal."""
    return _SEPARATORS.sub("", text).casefold()


def _printable_text(raw: bytes, min_ratio: float = 0.85) -> str | None:
    """Decode `raw` as UTF-8 text, or None if it looks like binary noise.

    The ratio is measured *before* invalid bytes are dropped: otherwise random
    bytes pass, because whatever printable ASCII survives the drop looks clean.
    """
    text = raw.decode("utf-8", errors="replace")
    if len(text) < 4:
        return None
    good = sum(1 for c in text if c != "\ufffd" and (c.isprintable() or c in "\r\n\t"))
    if good / len(text) < min_ratio:
        return None
    cleaned = text.replace("\ufffd", "")
    return cleaned if len(cleaned) >= 4 else None


def _readable_runs(raw: bytes) -> list[str]:
    text = raw.decode("utf-8", errors="replace")
    runs = _READABLE_RUN.findall(text)
    total = sum(len(r) for r in runs)
    if total < _MIN_SALVAGED_CHARS or total < _MIN_SALVAGED_SHARE * len(text):
        return []
    return runs[:_MAX_SALVAGED_RUNS]


def _b64(token: str) -> list[bytes]:
    token = token.rstrip("=").replace("-", "+").replace("_", "/")
    out: list[bytes] = []
    # Try all four alignments: the encoded value may be preceded by junk.
    for offset in range(4):
        chunk = token[offset:]
        if len(chunk) % 4 == 1:
            chunk = chunk[:-1]
        if len(chunk) < 4:
            continue
        try:
            out.append(base64.b64decode(chunk + "=" * (-len(chunk) % 4)))
        except (binascii.Error, ValueError):
            continue
    return out


def _dec_base64(text: str) -> list[tuple[str, str]]:
    parts: list[str] = []
    seen_tokens: set[str] = set()
    for pattern in (_B64_TOKEN, _B64_TOKEN_WS):
        for m in pattern.finditer(text):
            # base64.b64decode() silently drops whitespace, so a secret split across lines
            # or with spaces inserted decodes exactly as if it had none.
            token = "".join(m.group(0).split()) if pattern is _B64_TOKEN_WS else m.group(0)
            if len(token) < 6 or token in seen_tokens:
                continue
            seen_tokens.add(token)
            for raw in _b64(token):
                if strict := _printable_text(raw):
                    parts.append(strict)
                elif len(token) >= _MIN_SALVAGE_TOKEN:
                    parts.extend(_readable_runs(raw))
    return [("base64", "\n".join(parts))] if parts else []


def _dec_base32(text: str) -> list[tuple[str, str]]:
    parts = []
    for m in _B32_TOKEN.finditer(text):
        token = m.group(0).rstrip("=").upper()
        try:
            raw = base64.b32decode(token + "=" * (-len(token) % 8))
        except (binascii.Error, ValueError):
            continue
        if t := _printable_text(raw):
            parts.append(t)
    return [("base32", "\n".join(parts))] if parts else []


def _dec_hex(text: str) -> list[tuple[str, str]]:
    parts: list[str] = []
    seen_tokens: set[str] = set()
    for pattern in (_HEX_TOKEN, _HEX_TOKEN_WS):
        for m in pattern.finditer(text):
            # bytes.fromhex() silently drops whitespace too.
            token = "".join(m.group(0).split()) if pattern is _HEX_TOKEN_WS else m.group(0)
            if len(token) < 8 or token in seen_tokens:
                continue
            seen_tokens.add(token)
            for candidate in {token, token[:-1], token[1:]}:
                if len(candidate) % 2 or not candidate:
                    continue
                try:
                    raw = bytes.fromhex(candidate)
                except ValueError:
                    continue
                if strict := _printable_text(raw):
                    parts.append(strict)
                elif len(token) >= _MIN_SALVAGE_TOKEN:
                    parts.extend(_readable_runs(raw))
    return [("hex", "\n".join(parts))] if parts else []


def _dec_url(text: str) -> list[tuple[str, str]]:
    if "%" not in text and "+" not in text:
        return []
    out = {unquote(text), unquote_plus(text)} - {text}
    return [("url", t) for t in sorted(out)]


def _dec_html(text: str) -> list[tuple[str, str]]:
    if "&" not in text:
        return []
    decoded = html.unescape(text)
    return [("html", decoded)] if decoded != text else []


def _dec_unicode_escape(text: str) -> list[tuple[str, str]]:
    if "\\u" not in text:
        return []
    decoded = _UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)
    return [("unicode-escape", decoded)] if decoded != text else []


def _dec_charcodes(text: str) -> list[tuple[str, str]]:
    parts = []
    for m in _CHARCODES.finditer(text):
        codes = [int(n) for n in re.findall(r"\d+", m.group(0))]
        if all(9 <= c <= 126 for c in codes):
            parts.append("".join(map(chr, codes)))
    return [("charcodes", "\n".join(parts))] if parts else []


def _dec_rot13(text: str) -> list[tuple[str, str]]:
    return [("rot13", codecs.decode(text, "rot13"))]


def _dec_reverse(text: str) -> list[tuple[str, str]]:
    return [("reverse", text[::-1])]


_DECODERS: tuple[Callable[[str], list[tuple[str, str]]], ...] = (
    _dec_url,
    _dec_html,
    _dec_unicode_escape,
    _dec_base64,
    _dec_hex,
    _dec_base32,
    _dec_charcodes,
    _dec_rot13,
    _dec_reverse,
)


def expand(text: str, *, max_depth: int = 4, max_variants: int = 256) -> list[tuple[str, str]]:
    """Return ``[(variant_text, via)]``; the first entry is the normalized input (via "")."""
    base = normalize(text)
    variants = [(base, "")]
    seen = {hash(base)}
    frontier = [(base, "")]
    for _ in range(max_depth):
        next_frontier: list[tuple[str, str]] = []
        for current, via in frontier:
            limit = _MAX_CHILD_FACTOR * len(current) + 1024
            for decoder in _DECODERS:
                for label, child in decoder(current):
                    child = normalize(child[:limit])
                    if not child or hash(child) in seen:
                        continue
                    seen.add(hash(child))
                    path = f"{via}>{label}" if via else label
                    variants.append((child, path))
                    next_frontier.append((child, path))
                    if len(variants) >= max_variants:
                        return variants
        frontier = next_frontier
        if not frontier:
            break
    return variants
