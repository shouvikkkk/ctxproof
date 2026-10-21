"""Content-addressed tool-output store for ctxproof.

* Blobs are addressed by ``blake2b-256`` of the raw bytes and kept under
  ``<home>/store/<aa>/<bb...>`` (git-style fan-out).
* ``manifest.sqlite`` maps hash -> metadata: command, stream, size,
  timestamps, classifier verdict, transforms applied, expiry.
* Re-storing identical bytes dedupes: one blob, and a hit counter for stats.

``ctxproof restore`` trusts nothing: it re-hashes the blob and asserts
equality with the marker before serving a single byte.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

from . import classifier as classifier_mod
from . import transforms as transforms_mod

__all__ = [
    "content_hash",
    "parse_marker",
    "make_marker",
    "Store",
    "build_envelope",
    "expand_envelope",
    "home_dir",
]

MARKER_SCHEME = "ctxproof://blake2/"
_HASH_RE = re.compile(r"\A[0-9a-f]{64}\Z")


def content_hash(data: bytes) -> str:
    """blake2b-256 hex digest of raw bytes."""
    return hashlib.blake2b(data, digest_size=32).hexdigest()


def make_marker(digest: str) -> str:
    return MARKER_SCHEME + digest


def parse_marker(marker: str) -> Optional[str]:
    """Return the hex digest for a valid marker, else None."""
    marker = marker.strip()
    if not marker.startswith(MARKER_SCHEME):
        return None
    digest = marker[len(MARKER_SCHEME):]
    return digest if _HASH_RE.match(digest) else None


def home_dir() -> Path:
    return Path(os.environ.get("CTXPROOF_HOME", Path.home() / ".ctxproof"))


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS captures (
    hash TEXT PRIMARY KEY,
    command TEXT,
    stream TEXT,
    exit_code INTEGER,
    duration_ms REAL,
    captured_at TEXT,
    cwd TEXT,
    tier TEXT,
    risk REAL,
    reasons TEXT,
    transforms TEXT,
    tables TEXT,
    raw_bytes INTEGER,
    payload_bytes INTEGER,
    hits INTEGER DEFAULT 1,
    expires_at TEXT
);
"""


class Store:
    """The on-disk content-addressed store + manifest."""

    def __init__(self, home: Optional[Path] = None):
        self.home = Path(home) if home else home_dir()
        self.blobs = self.home / "store"
        self.blobs.mkdir(parents=True, exist_ok=True)
        self.db_path = self.home / "manifest.sqlite"
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    # -- low-level blob ops -------------------------------------------------
    def _blob_path(self, digest: str) -> Path:
        return self.blobs / digest[:2] / digest[2:]

    def put(self, data: bytes, meta: Dict) -> Tuple[str, bool]:
        """Store ``data``; return (digest, deduped)."""
        digest = content_hash(data)
        path = self._blob_path(digest)
        deduped = path.exists()
        if not deduped:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(data)
            os.replace(tmp, path)
        row = self.lookup(digest)
        if row is None:
            self._conn.execute(
                """INSERT INTO captures
                   (hash, command, stream, exit_code, duration_ms, captured_at,
                    cwd, tier, risk, reasons, transforms, tables,
                    raw_bytes, payload_bytes, hits, expires_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)""",
                (
                    digest, meta.get("command"), meta.get("stream"),
                    meta.get("exit_code"), meta.get("duration_ms"),
                    meta.get("captured_at", _utcnow()), meta.get("cwd"),
                    meta.get("tier"), meta.get("risk"),
                    json.dumps(meta.get("reasons", [])),
                    json.dumps(meta.get("transforms", [])),
                    json.dumps(meta.get("tables", {})),
                    len(data), meta.get("payload_bytes", len(data)),
                    meta.get("expires_at"),
                ),
            )
        else:
            self._conn.execute(
                "UPDATE captures SET hits = hits + 1 WHERE hash = ?", (digest,))
        self._conn.commit()
        return digest, deduped

    def get(self, digest: str) -> Optional[bytes]:
        path = self._blob_path(digest)
        if not path.exists():
            return None
        return path.read_bytes()

    def lookup(self, digest: str) -> Optional[Dict]:
        cur = self._conn.execute(
            "SELECT * FROM captures WHERE hash = ?", (digest,))
        row = cur.fetchone()
        if row is None:
            return None
        cols = [d[0] for d in cur.description]
        return dict(zip(cols, row))

    def set_expiry(self, digest: str, ttl_days: float) -> bool:
        exp = (datetime.datetime.now(datetime.timezone.utc)
               + datetime.timedelta(days=ttl_days)).isoformat()
        cur = self._conn.execute(
            "UPDATE captures SET expires_at = ? WHERE hash = ?", (exp, digest))
        self._conn.commit()
        return cur.rowcount > 0

    def prune(self, older_than_days: float) -> Tuple[int, int]:
        """Delete blobs+rows older than N days. Returns (blobs, rows)."""
        cutoff = (datetime.datetime.now(datetime.timezone.utc)
                  - datetime.timedelta(days=older_than_days)).isoformat()
        cur = self._conn.execute(
            "SELECT hash FROM captures WHERE captured_at < ?", (cutoff,))
        hashes = [r[0] for r in cur.fetchall()]
        blobs = 0
        for digest in hashes:
            p = self._blob_path(digest)
            if p.exists():
                p.unlink()
                blobs += 1
        cur = self._conn.execute(
            "DELETE FROM captures WHERE captured_at < ?", (cutoff,))
        self._conn.commit()
        return blobs, cur.rowcount

    def stats(self) -> Dict:
        cur = self._conn.execute(
            """SELECT COUNT(*), SUM(raw_bytes), SUM(payload_bytes),
                      SUM(hits), SUM(raw_bytes - payload_bytes)
               FROM captures""")
        n, raw, payload, hits, saved = cur.fetchone()
        cur = self._conn.execute("SELECT COUNT(*) FROM captures WHERE hits > 1")
        dedup_rows = cur.fetchone()[0]
        return {
            "captures": n or 0,
            "unique_blobs": n or 0,
            "bytes_stored": raw or 0,
            "payload_bytes": payload or 0,
            "total_hits": hits or 0,
            "dedup_hits": (hits or 0) - (n or 0),
            "rows_with_dedup": dedup_rows or 0,
            "bytes_saved": saved or 0,
            "est_tokens_saved": (saved or 0) // 4,
        }

    def close(self) -> None:
        self._conn.close()


# ---------------------------------------------------------------------------
# Envelopes: the machine-readable compressed payload + retrieval marker
# ---------------------------------------------------------------------------

def build_envelope(data: bytes, meta: Dict,
                   min_bytes: int = classifier_mod.DEFAULT_MIN_BYTES) -> Dict:
    """Classify + transform ``data`` and return the envelope dict.

    The envelope carries everything ``restore`` needs: the marker (content
    hash of the *original* bytes), the tier, the transform tables, and the
    transformed payload (base64). Byte-exact restore is always possible
    because every transform round-trips.
    """
    verdict = classifier_mod.classify(meta.get("command", ""), data,
                                      min_bytes=min_bytes)
    tier = verdict.tier
    transformed, tables = transforms_mod.apply(data, tier)
    envelope = {
        "format": "ctxproof/envelope-1",
        "marker": make_marker(content_hash(data)),
        "hash_algo": "blake2b-256",
        "tier": tier,
        "risk": round(verdict.risk, 3),
        "reasons": verdict.reasons,
        "command": meta.get("command"),
        "exit_code": meta.get("exit_code"),
        "duration_ms": meta.get("duration_ms"),
        "captured_at": meta.get("captured_at", _utcnow()),
        "transforms": list(tables.keys()),
        "tables": tables,
        "payload_b64": base64.b64encode(transformed).decode("ascii"),
        "raw_bytes": len(data),
        "payload_bytes": len(transformed),
    }
    return envelope


def expand_envelope(envelope: Dict) -> bytes:
    """Re-expand an envelope's payload back to the original bytes.

    Verifies the result against the envelope's marker hash — raises
    ``ValueError`` if the envelope is corrupt. Never returns unverified bytes.
    """
    if envelope.get("format") != "ctxproof/envelope-1":
        raise ValueError("not a ctxproof envelope")
    digest = parse_marker(envelope.get("marker", ""))
    if digest is None:
        raise ValueError("envelope has an invalid marker")
    payload = base64.b64decode(envelope["payload_b64"])
    tables = envelope.get("tables", {})
    tier = envelope.get("tier", "passthrough")
    try:
        original = transforms_mod.revert(payload, tier, tables)
    except transforms_mod.TransformError as e:
        raise ValueError(f"envelope payload failed to invert: {e}")
    if content_hash(original) != digest:
        raise ValueError("envelope payload does not match its marker hash")
    return original


def capture_command(argv, timeout: Optional[float] = None) -> Dict:
    """Run ``argv``, capturing raw stdout/stderr BYTES (not text)."""
    import subprocess
    started = time.monotonic()
    proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout)
    duration_ms = (time.monotonic() - started) * 1000
    return {
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "exit_code": proc.returncode,
        "duration_ms": duration_ms,
        "cwd": os.getcwd(),
        "captured_at": _utcnow(),
    }
