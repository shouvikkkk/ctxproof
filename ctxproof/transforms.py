"""Reversible, byte-exact text transforms for ctxproof.

Every transform in this module is *lossless*: ``decode(encode(x)) == x`` for
every byte string ``x``, including binary and non-UTF-8 input. The "lossy"
tier in ctxproof does not mean information loss — it means we apply more
aggressive transforms to content the classifier judged safe to shrink hard.
All transforms are still byte-exact reversible, which is what lets
``ctxproof restore`` re-hydrate the original bytes and assert hash equality.

Design
------
* Transforms operate on ``bytes``. Text-oriented transforms first try a
  strict UTF-8 decode; on failure they are the identity (still reversible).
* Markers use the ASCII "unit separator" byte ``\\x1f`` as a sentinel. The
  encode pipeline first doubles every literal ``\\x1f`` byte
  (``\\x1f`` -> ``\\x1f\\x1f``); decode reverses this after all inverse
  transforms. Because real content can never contain a *single* ``\\x1f``
  after escaping, markers can never collide with payload content.
* Line-level transforms insert whole marker *lines* of the form
  ``\\x1fCTXPROOF\\x1f<KIND>\\x1f<payload>\\x1f``.
* Inline transforms (timestamps, whitespace) replace text in place with
  marker tokens that carry everything needed to invert them.
* Each transform declares ``lossless = True`` and returns an auxiliary
  ``tables`` dict that travels in the envelope; ``decode`` fails closed
  (raises :class:`TransformError`) if a table it needs is missing.
"""

from __future__ import annotations

import base64
import calendar
import datetime
import re
from typing import Dict, List, Tuple

__all__ = [
    "TransformError",
    "Transform",
    "LineRunDedup",
    "TimestampCollapse",
    "RepeatedBlockFold",
    "WhitespaceCollapse",
    "TRANSFORMS",
    "LOSSLESS_TIER",
    "LOSSY_TIER",
    "apply",
    "revert",
]

SENT = b"\x1f"
PREFIX = SENT + b"CTXPROOF" + SENT  # \x1fCTXPROOF\x1f


class TransformError(Exception):
    """Raised when a transform cannot be inverted (corrupt envelope)."""


class Transform:
    """Base class: a named, byte-exact reversible transform."""

    name: str = "base"
    # Every ctxproof transform is lossless and must round-trip. This flag is
    # asserted by the test-suite for every registered transform.
    lossless: bool = True

    def encode(self, data: bytes) -> Tuple[bytes, Dict]:
        raise NotImplementedError

    def decode(self, data: bytes, tables: Dict) -> bytes:
        raise NotImplementedError


def _escape(data: bytes) -> bytes:
    """Double every literal sentinel byte so markers can't collide."""
    return data.replace(SENT, SENT + SENT)


def _unescape(data: bytes) -> bytes:
    return data.replace(SENT + SENT, SENT)


# ---------------------------------------------------------------------------
# 1. line-run-dedup — collapse runs of identical consecutive lines
# ---------------------------------------------------------------------------

_RUN_RE = re.compile(rb"\x1fCTXPROOF\x1fRUN\x1f(\d+)\x1f\Z")


class LineRunDedup(Transform):
    """Collapse runs of N>=3 identical consecutive lines into ``count + line``.

    Byte-level: works on any bytes, no decoding needed. The marker line is
    followed by a single copy of the repeated line; decode re-expands it.
    """

    name = "line-run-dedup"
    MIN_RUN = 3

    def encode(self, data: bytes) -> Tuple[bytes, Dict]:
        lines = data.split(b"\n")
        out: List[bytes] = []
        i = 0
        n = len(lines)
        while i < n:
            j = i + 1
            while j < n and lines[j] == lines[i]:
                j += 1
            run = j - i
            if run >= self.MIN_RUN:
                out.append(PREFIX + b"RUN" + SENT + str(run).encode() + SENT)
                out.append(lines[i])
            else:
                out.extend(lines[i:j])
            i = j
        return b"\n".join(out), {}

    def decode(self, data: bytes, tables: Dict) -> bytes:
        lines = data.split(b"\n")
        out: List[bytes] = []
        i = 0
        n = len(lines)
        while i < n:
            m = _RUN_RE.match(lines[i])
            if m:
                if i + 1 >= n:
                    raise TransformError("line-run-dedup: marker with no content line")
                count = int(m.group(1))
                content = lines[i + 1]
                if _RUN_RE.match(content):
                    raise TransformError("line-run-dedup: nested markers")
                out.extend([content] * count)
                i += 2
            else:
                out.append(lines[i])
                i += 1
        return b"\n".join(out)


# ---------------------------------------------------------------------------
# 2. timestamp-collapse — collapse log timestamps to microsecond deltas
# ---------------------------------------------------------------------------
#
# Matches the overwhelmingly common log format: YYYY-MM-DD[ T]HH:MM:SS with an
# optional fractional part, no timezone suffix. Timezone-suffixed or exotic
# timestamps are deliberately left alone (documented limitation).
#
# The first timestamp in the payload becomes the base; every occurrence is
# replaced by its integer-microsecond delta from the base plus its format
# variant (space vs 'T' separator, fractional digit count). Integer
# arithmetic keeps the round-trip exact — no float drift, no strftime
# re-formatting surprises.

_TS_RE = re.compile(
    rb"(?P<date>(?P<y>\d{4})-(?P<mo>\d{2})-(?P<d>\d{2}))"
    rb"(?P<sep>[T ])"
    rb"(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
    rb"(?P<frac>\.\d{1,6})?"
)
_TS_TOKEN_RE = re.compile(rb"\x1fCTXPROOF\x1fTS\x1f(-?\d+)\x1f([ST])(\d)\x1f")


def _parse_ts(m: "re.Match") -> Tuple[int, bytes, int] | None:
    """Return (epoch_us, sep_byte, frac_digits) or None if invalid."""
    try:
        dt = datetime.datetime(
            int(m.group("y")), int(m.group("mo")), int(m.group("d")),
            int(m.group("h")), int(m.group("mi")), int(m.group("s")),
        )
    except ValueError:
        return None  # e.g. month 13 — not a real timestamp
    epoch_us = calendar.timegm(dt.timetuple()) * 1_000_000
    frac = m.group("frac")
    frac_digits = 0
    if frac:
        digits = frac[1:]  # strip the dot
        frac_digits = len(digits)
        epoch_us += int(digits.ljust(6, b"0")[:6])
    sep = m.group("sep")
    return epoch_us, sep, frac_digits


def _format_ts(epoch_us: int, sep: bytes, frac_digits: int) -> bytes:
    secs, us = divmod(epoch_us, 1_000_000)
    dt = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=secs)
    out = (
        f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}"
        f"{sep.decode('ascii')}"
        f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"
    ).encode("ascii")
    if frac_digits:
        out += b"." + str(us).zfill(6)[:frac_digits].encode("ascii")
    return out


class TimestampCollapse(Transform):
    """Replace timestamps with microsecond deltas from the payload's first.

    Token: ``\\x1fCTXPROOF\\x1fTS\\x1f<delta_us>\\x1f<S|T><fracdigits>\\x1f``.
    The base epoch travels in ``tables["timestamp-collapse"]["base_epoch_us"]``.
    """

    name = "timestamp-collapse"

    def encode(self, data: bytes) -> Tuple[bytes, Dict]:
        try:
            data.decode("utf-8")  # validity check only; regexes are bytes-based
        except UnicodeDecodeError:
            return data, {}
        base_us: int | None = None

        def sub(m: "re.Match") -> bytes:
            nonlocal base_us
            parsed = _parse_ts(m)
            if parsed is None:
                return m.group(0)
            epoch_us, sep, frac_digits = parsed
            if base_us is None:
                base_us = epoch_us
            delta = epoch_us - base_us
            variant = b"S" if sep == b" " else b"T"
            return (
                PREFIX + b"TS" + SENT
                + str(delta).encode("ascii") + SENT
                + variant + str(frac_digits).encode("ascii") + SENT
            )

        out = _TS_RE.sub(sub, data)
        tables = {"base_epoch_us": base_us} if base_us is not None else {}
        return out, tables

    def decode(self, data: bytes, tables: Dict) -> bytes:
        base_us = tables.get("base_epoch_us")
        if base_us is None:
            # Fail closed: tokens without a base table means a corrupt envelope.
            if _TS_TOKEN_RE.search(data):
                raise TransformError(
                    "timestamp-collapse: tokens present but base_epoch_us table missing"
                )
            return data

        def sub(m: "re.Match") -> bytes:
            delta = int(m.group(1))
            variant = m.group(2)
            frac_digits = int(m.group(3))
            sep = b" " if variant == b"S" else b"T"
            return _format_ts(base_us + delta, sep, frac_digits)

        return _TS_TOKEN_RE.sub(sub, data)


# ---------------------------------------------------------------------------
# 3. repeated-block-fold — fold repeated multi-line blocks (banners, etc.)
# ---------------------------------------------------------------------------


class RepeatedBlockFold(Transform):
    """Fold repeated blocks of >=2 identical consecutive lines.

    Finds the repeated blocks with the biggest byte savings (greedy, largest
    first, non-overlapping), replaces every occurrence with a marker line,
    and stores each block's exact bytes (base64) in the tables. Skipped
    entirely for inputs over 512 KiB to bound the O(n * heights) scan.
    """

    name = "repeated-block-fold"
    MAX_BYTES = 512 * 1024
    MIN_HEIGHT = 2
    MAX_HEIGHT = 8
    MIN_SAVINGS = 64

    def encode(self, data: bytes) -> Tuple[bytes, Dict]:
        if len(data) > self.MAX_BYTES:
            return data, {}
        lines = data.split(b"\n")
        if len(lines) < self.MIN_HEIGHT * 2:
            return data, {}

        # Find candidate blocks, biggest savings first.
        candidates: List[Tuple[int, int, Tuple[bytes, ...]]] = []
        for height in range(self.MIN_HEIGHT, self.MAX_HEIGHT + 1):
            counts: Dict[Tuple[bytes, ...], int] = {}
            for i in range(len(lines) - height + 1):
                key = tuple(lines[i:i + height])
                counts[key] = counts.get(key, 0) + 1
            for key, c in counts.items():
                if c >= 2:
                    block_bytes = sum(len(l) + 1 for l in key)
                    savings = (c - 1) * block_bytes
                    if savings >= self.MIN_SAVINGS:
                        candidates.append((savings, height, key))
        if not candidates:
            return data, {}
        candidates.sort(key=lambda t: (-t[0], -t[1]))

        blocks: List[Tuple[bytes, ...]] = []
        claimed: List[Tuple[int, int]] = []  # (start, end) line ranges, folded

        def overlaps(s: int, e: int) -> bool:
            return any(s < ce and e > cs for cs, ce in claimed)

        chosen: List[Tuple[int, Tuple[bytes, ...]]] = []  # (id, block)
        for _savings, height, key in candidates:
            # find non-overlapping occurrences of this block
            occ: List[int] = []
            i = 0
            while i <= len(lines) - height:
                if tuple(lines[i:i + height]) == key and not overlaps(i, i + height):
                    occ.append(i)
                    claimed.append((i, i + height))
                    i += height
                else:
                    i += 1
            if len(occ) >= 2:
                bid = len(blocks)
                blocks.append(key)
                chosen.append((bid, key, occ))

        if not chosen:
            return data, {}

        # Replace occurrences with marker lines, scanning left to right.
        repl: Dict[int, Tuple[int, int]] = {}  # start -> (id, height)
        for bid, key, occ in chosen:
            for s in occ:
                repl[s] = (bid, len(key))
        out: List[bytes] = []
        i = 0
        n = len(lines)
        while i < n:
            if i in repl:
                bid, height = repl[i]
                out.append(PREFIX + b"BLK" + SENT + str(bid).encode() + SENT)
                i += height
            else:
                out.append(lines[i])
                i += 1
        tables = {
            "blocks": {
                str(bid): base64.b64encode(b"\n".join(block)).decode("ascii")
                for bid, block in enumerate(blocks)
            }
        }
        return b"\n".join(out), tables

    def decode(self, data: bytes, tables: Dict) -> bytes:
        raw_blocks = tables.get("blocks")
        blk_re = re.compile(rb"\x1fCTXPROOF\x1fBLK\x1f(\d+)\x1f\Z")
        if raw_blocks is None:
            # Fail closed: markers without a blocks table means a corrupt envelope.
            if any(blk_re.match(l) for l in data.split(b"\n")):
                raise TransformError(
                    "repeated-block-fold: markers present but blocks table missing"
                )
            return data
        blocks = {
            bid: base64.b64decode(b64).split(b"\n")
            for bid, b64 in raw_blocks.items()
        }
        out: List[bytes] = []
        for line in data.split(b"\n"):
            m = blk_re.match(line)
            if m:
                bid = m.group(1).decode("ascii")
                if bid not in blocks:
                    raise TransformError(f"repeated-block-fold: unknown block id {bid}")
                out.extend(blocks[bid])
            else:
                out.append(line)
        return b"\n".join(out)


# ---------------------------------------------------------------------------
# 4. whitespace-collapse — collapse long leading-whitespace runs
# ---------------------------------------------------------------------------

_WS_TOKEN_RE = re.compile(rb"\x1fCTXPROOF\x1fWS\x1f([A-Za-z0-9+/=]+)\x1f")
_WS_LINE_RE = re.compile(rb"\A([ \t]{8,})(.*)\Z", re.DOTALL)


class WhitespaceCollapse(Transform):
    """Collapse leading runs of >=8 spaces/tabs into a marker token.

    The exact whitespace bytes are base64'd into the token itself, so the
    transform is self-inverting with no table needed. Only applied to the
    LOSSY tier (classifier keeps source code on the lossless path anyway),
    but still byte-exact.
    """

    name = "whitespace-collapse"
    MIN_RUN = 8

    def encode(self, data: bytes) -> Tuple[bytes, Dict]:
        out_lines: List[bytes] = []
        for line in data.split(b"\n"):
            m = _WS_LINE_RE.match(line)
            if m:
                ws, rest = m.group(1), m.group(2)
                token = (
                    PREFIX + b"WS" + SENT
                    + base64.b64encode(ws) + SENT
                )
                out_lines.append(token + rest)
            else:
                out_lines.append(line)
        return b"\n".join(out_lines), {}

    def decode(self, data: bytes, tables: Dict) -> bytes:
        def sub(m: "re.Match") -> bytes:
            return base64.b64decode(m.group(1))

        return _WS_TOKEN_RE.sub(sub, data)


# ---------------------------------------------------------------------------
# Registry, tiers, pipeline
# ---------------------------------------------------------------------------

TRANSFORMS: Dict[str, Transform] = {
    t.name: t
    for t in (
        LineRunDedup(),
        TimestampCollapse(),
        RepeatedBlockFold(),
        WhitespaceCollapse(),
    )
}

# Lossless tier: reversible marker transforms only (safe for exact-text).
LOSSLESS_TIER = ["line-run-dedup"]
# Lossy tier: everything above, for content the classifier judged safe.
# Still byte-exact reversible — "lossy" refers to compression aggressiveness.
LOSSY_TIER = ["line-run-dedup", "timestamp-collapse", "repeated-block-fold",
              "whitespace-collapse"]

_TIER_MAP = {
    "lossless": LOSSLESS_TIER,
    "lossy": LOSSY_TIER,
    "passthrough": [],
}


def apply(data: bytes, tier: str) -> Tuple[bytes, Dict[str, Dict]]:
    """Encode ``data`` with every transform in ``tier``.

    Returns (transformed_bytes, tables) where tables maps transform name ->
    its auxiliary table for the envelope. The global sentinel escape is
    applied first so markers can never collide with payload content.
    """
    names = _TIER_MAP.get(tier)
    if names is None:
        raise TransformError(f"unknown tier: {tier!r}")
    tables: Dict[str, Dict] = {}
    out = _escape(data)
    for name in names:
        t = TRANSFORMS[name]
        out, t_tables = t.encode(out)
        tables[name] = t_tables
    return out, tables


def revert(data: bytes, tier: str, tables: Dict[str, Dict]) -> bytes:
    """Invert :func:`apply`. Raises TransformError on any inconsistency."""
    names = _TIER_MAP.get(tier)
    if names is None:
        raise TransformError(f"unknown tier: {tier!r}")
    out = data
    for name in reversed(names):
        t = TRANSFORMS[name]
        out = t.decode(out, tables.get(name, {}))
    return _unescape(out)
