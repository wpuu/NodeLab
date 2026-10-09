"""Bounded, explicit subscription containers; no fetching or protocol conversion."""
from __future__ import annotations

import base64
import binascii
import re

from nodelab.inventory import MAX_INPUT_BYTES, InventoryInputError


def decode_subscription_input(data: bytes | str, *, input_format: str = "uri_lines") -> bytes:
    """Return private parser input, decoding a Base64 container exactly once.

    The default preserves URI lines without guessing. Base64 accepts standard
    or URL-safe alphabets, canonical padding or entirely omitted padding, an
    initial UTF-8 BOM, and ASCII SP/HT/CR/LF only. Both byte limits apply before
    parsing; decoded lines, including invalid UTF-8, must reach the ledger.
    Returned bytes are private and must never be logged or exported.
    """
    if type(input_format) is not str or input_format not in {"uri_lines", "base64"}:
        raise InventoryInputError("INVALID_ARGUMENTS")
    if type(data) is str:
        if len(data) > MAX_INPUT_BYTES:
            raise InventoryInputError("INPUT_TOO_LARGE")
        try:
            data = data.encode("utf-8", errors="strict")
        except UnicodeError:
            raise InventoryInputError("INVALID_UTF8") from None
    if type(data) is not bytes:
        raise InventoryInputError("INPUT_TYPE_INVALID")
    if len(data) > MAX_INPUT_BYTES:
        raise InventoryInputError("INPUT_TOO_LARGE")
    if input_format == "uri_lines":
        return data

    encoded = data[3:] if data.startswith(b"\xef\xbb\xbf") else data
    encoded = encoded.translate(None, b" \t\r\n")
    if (not encoded or re.fullmatch(rb"[A-Za-z0-9+/_-]+={0,2}", encoded) is None
            or (any(c in encoded for c in (b"+", b"/"))
                and any(c in encoded for c in (b"-", b"_")))):
        raise InventoryInputError("INVALID_BASE64")
    body = encoded.rstrip(b"=")
    supplied_padding = len(encoded) - len(body)
    expected_padding = (-len(body)) % 4
    if expected_padding == 3 or (supplied_padding and supplied_padding != expected_padding):
        raise InventoryInputError("INVALID_BASE64")
    normalized = body.translate(bytes.maketrans(b"-_", b"+/")) + b"=" * expected_padding
    try:
        decoded = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError):
        raise InventoryInputError("INVALID_BASE64") from None
    if len(decoded) > MAX_INPUT_BYTES:
        raise InventoryInputError("INPUT_TOO_LARGE")
    if base64.b64encode(decoded) != normalized:
        raise InventoryInputError("INVALID_BASE64")
    return decoded
