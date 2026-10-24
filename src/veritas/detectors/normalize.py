"""Text normalisation that undoes the obfuscation used by attack variants.

Pattern matching on raw text is easy to evade: an attacker inserts zero-width
spaces, swaps Latin letters for Cyrillic look-alikes, or writes in leetspeak.
Normalising first means one clean set of patterns catches the plain attack and
its obfuscated variants, which is why the pattern detector runs on the output of
:func:`normalize` rather than on raw input. The transforms here are the inverses
of those in ``veritas.corpus.variants``.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍﻿⁠"), None)

# Reverse of the corpus homoglyph map plus the most common Cyrillic look-alikes.
_HOMOGLYPH_FOLD = {
    "а": "a", "е": "e", "о": "o", "с": "c", "р": "p",
    "х": "x", "у": "y", "і": "i", "ԁ": "d", "һ": "h",
}
_HOMOGLYPH_TABLE = {ord(k): v for k, v in _HOMOGLYPH_FOLD.items()}

_DELEET = str.maketrans({"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t"})

_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def strip_zero_width(text: str) -> str:
    """Remove zero-width and word-joiner characters used to split trigger words."""
    return text.translate(_ZERO_WIDTH)


def fold_homoglyphs(text: str) -> str:
    """Map common non-Latin look-alike letters back to ASCII."""
    return unicodedata.normalize("NFKC", text).translate(_HOMOGLYPH_TABLE)


def deleet(text: str) -> str:
    """Undo digit-for-letter leetspeak substitutions."""
    return text.translate(_DELEET)


def normalize(text: str) -> str:
    """Return a lower-cased, de-obfuscated, whitespace-collapsed form for matching.

    Collapsing runs of whitespace defeats padding attacks that space words out to
    break a plain-text pattern, while keeping the token sequence intact.
    """
    folded = fold_homoglyphs(strip_zero_width(text))
    collapsed = re.sub(r"\s+", " ", deleet(folded))
    return collapsed.strip().lower()


def decode_base64_segments(text: str) -> list[str]:
    """Return UTF-8 decodings of any base64-looking segments in ``text``.

    Used by the encoding detector to read smuggled instructions. Segments that do
    not decode to valid UTF-8 are skipped rather than raising.
    """
    out: list[str] = []
    for match in _B64_RE.findall(text):
        if len(match) % 4 != 0:
            continue
        try:
            decoded = base64.b64decode(match, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded.isprintable():
            out.append(decoded)
    return out


def rot13(text: str) -> str:
    """ROT13 the text so a ciphered instruction can be read back."""
    return codecs.encode(text, "rot13")


def has_base64_blob(text: str) -> bool:
    """True if the text contains a decodable base64 segment of real length."""
    return bool(decode_base64_segments(text))
