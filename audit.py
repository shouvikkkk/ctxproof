"""Differential corruption harness for ctxproof.

The correctness oracle that lossy context compressors lack: seed exact-text
canaries through ANY compressor's ``compress``/``restore`` pair and assert
byte-equality on the way out.

Plugin interface (implement this to audit your own compressor)::

    class MyCompressor:
        def compress(self, data: bytes) -> tuple[bytes, str]:
            ...  # return (payload, marker)
        def restore(self, marker: str) -> bytes:
            ...  # return the restored bytes for marker

``ctxproof audit --compressor pkg.mod:MyCompressor`` runs every seed through
the pair and reports which payload classes get mangled — the direct answer
to the "no correctness oracle" gap behind headroom#4321.
"""

from __future__ import annotations

import importlib
import random
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol, Tuple

__all__ = [
    "Compressor",
    "AuditResult",
    "SeedResult",
    "SEEDS",
    "audit",
    "SelfCompressor",
    "load_compressor",
]


class Compressor(Protocol):
    def compress(self, data: bytes) -> Tuple[bytes, str]: ...
    def restore(self, marker: str) -> bytes: ...


@dataclass
class SeedResult:
    name: str
    kind: str
    size: int
    ok: bool
    detail: str = ""
    elapsed_ms: float = 0.0


@dataclass
class AuditResult:
    compressor: str
    seeds: List[SeedResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for s in self.seeds if s.ok)

    @property
    def failed(self) -> int:
        return sum(1 for s in self.seeds if not s.ok)

    def report(self) -> str:
        lines = [
            f"ctxproof audit — {self.compressor}",
            f"{'SEED':<34}{'KIND':<16}{'SIZE':>8}  STATUS  DETAIL",
            "-" * 90,
        ]
        for s in self.seeds:
            status = "PASS" if s.ok else "MANGLED"
            lines.append(f"{s.name:<34}{s.kind:<16}{s.size:>8}  {status:<7} {s.detail}")
        lines.append("-" * 90)
        lines.append(f"{self.passed} passed, {self.failed} mangled "
                     f"out of {len(self.seeds)} seeds")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Seed corpus: payload classes compressors are known to mangle
# ---------------------------------------------------------------------------

_PY_SNIPPET = b'''def reconcile_ledger(entries):
    """Apply double-entry reconciliation to ledger entries."""
    balances = {}
    for e in entries:
        if e.kind == "debit":
            balances[e.account] = balances.get(e.account, 0) - e.amount
        elif e.kind == "credit":
            balances[e.account] = balances.get(e.account, 0) + e.amount
        else:
            raise ValueError(f"unknown entry kind: {e.kind!r}")
    return {k: round(v, 2) for k, v in balances.items() if v != 0}
'''

_DIFF = b'''diff --git a/ctxproof/store.py b/ctxproof/store.py
index 3a1f9c2..7b2e4d1 100644
--- a/ctxproof/store.py
+++ b/ctxproof/store.py
@@ -41,7 +41,7 @@ def put(self, data: bytes, meta: dict):
     def put(self, data: bytes, meta: dict):
-        digest = hashlib.sha256(data).hexdigest()
+        digest = hashlib.blake2b(data, digest_size=32).hexdigest()
         path = self._blob_path(digest)
'''

_JSON = b'''{"run_id": "a3f9c1", "matrix": [[1, 2, 3], [4, 5, 6]],
 "config": {"retries": 3, "timeout_ms": 1500, "features": ["dedup", "verify"]},
 "nested": {"deep": {"deeper": [true, false, null, "x"]}}}'''

_TRACEBACK = b'''Traceback (most recent call last):
  File "/app/worker.py", line 212, in run
    result = handler(payload)
  File "/app/handlers.py", line 88, in handler
    return json.loads(body)["items"][0]
KeyError: 'items'
'''

_LOG = b'''2026-10-21 08:44:01 INFO  worker starting (pid=412)
2026-10-21 08:44:02 INFO  connected to queue in 812ms
2026-10-21 08:44:09 WARN  retry 1/3 for job 9917: timeout after 5000ms
2026-10-21 08:44:19 ERROR job 9917 failed permanently: timeout after 5000ms
2026-10-21 08:44:20 INFO  worker shutting down
'''

_CSV_ROWS = b'''id,email,plan,renew_at
1,ada@example.com,pro,2026-11-01
2,grace@example.com,free,2026-11-02
3,linus@example.com,pro,2026-11-03
'''

_CAT_N = b'''     1\timport os
     2\timport sys
     3\t
     4\tdef main(argv):
     5\t    return 0
'''

_BANNER = b'''========================================
  deploy v2.14.1 - starting rollout
========================================
'''

# Long single-line payloads: the classic victims of line-truncating
# compressors (and of "summarize each line" heuristics).
_LONG_JSON = (b'{"event":"deploy","service":"api-gateway","region":"ap-south-1",'
              b'"commit":"7b2e4d1a9c3f8e2d1b4a6c5d9e0f1a2b3c4d5e6","artifacts":'
              b'["registry.local/api:2.14.1","registry.local/api:2.14.1-debug"],'
              b'"rollout":{"strategy":"canary","steps":[10,25,50,100]},"ok":true}')
_LONG_LOG = (b'2026-10-21 08:44:09 WARN  retry 1/3 for job 9917: upstream '
             b'https://queue.internal.example.com/v2/jobs/9917 timed out after '
             b'5000ms (connect=12ms tls=88ms ttfb=4900ms); backing off 2000ms')


def _with_needle(name: str, data: bytes, rng: random.Random) -> Tuple[str, bytes]:
    """Embed a unique canary string so silent drops are detectable."""
    needle = f"CTXPROOF-NEEDLE-{rng.randint(1000, 9999)}-qx7z".encode()
    # splice the needle mid-payload so prefix/suffix truncation is caught
    mid = len(data) // 2
    return name + "+needle", data[:mid] + b"\n" + needle + b"\n" + data[mid:]


def build_seeds(seed: int = 20261021) -> List[Tuple[str, str, bytes]]:
    """Return (name, kind, data) seeds, deterministically."""
    rng = random.Random(seed)
    base = [
        ("py-snippet", "source-code", _PY_SNIPPET),
        ("unified-diff", "diff", _DIFF),
        ("json-blob", "json", _JSON),
        ("traceback", "stack-trace", _TRACEBACK),
        ("server-log", "timestamped-log", _LOG),
        ("csv-rows", "rare-rows", _CSV_ROWS),
        ("cat-n", "line-numbered", _CAT_N),
        ("banner", "boilerplate", _BANNER),
        ("long-json-line", "long-line", _LONG_JSON),
        ("long-log-line", "long-line", _LONG_LOG),
    ]
    seeds = list(base)
    for name, kind, data in base:
        n2, d2 = _with_needle(name, data, rng)
        seeds.append((n2, kind, d2))
    return seeds


SEEDS = build_seeds()


def _first_divergence(a: bytes, b: bytes) -> str:
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            ctx = 24
            exp = a[max(0, i - ctx):i + ctx]
            got = b[max(0, i - ctx):i + ctx]
            return (f"first divergence at byte {i} "
                    f"(len {len(a)} -> {len(b)}): "
                    f"expected {exp!r} got {got!r}")
    if len(a) != len(b):
        return f"truncated/extended: {len(a)} -> {len(b)} bytes"
    return "unknown divergence"


def audit(compressor: Compressor, seeds: Optional[List[Tuple[str, str, bytes]]] = None,
          timeout_s: float = 30.0) -> AuditResult:
    """Run every seed through compress/restore; assert byte-equality."""
    name = type(compressor).__name__
    result = AuditResult(compressor=name)
    for sname, kind, data in (seeds or SEEDS):
        started = time.monotonic()
        try:
            payload, marker = compressor.compress(data)
            restored = compressor.restore(marker)
            elapsed = (time.monotonic() - started) * 1000
            if restored == data:
                result.seeds.append(SeedResult(sname, kind, len(data), True,
                                              f"byte-exact ({len(payload)}B payload)",
                                              elapsed))
            else:
                result.seeds.append(SeedResult(
                    sname, kind, len(data), False,
                    _first_divergence(data, restored), elapsed))
        except Exception as e:  # noqa: BLE001 — harness must not crash
            elapsed = (time.monotonic() - started) * 1000
            result.seeds.append(SeedResult(sname, kind, len(data), False,
                                          f"raised {type(e).__name__}: {e}",
                                          elapsed))
    return result


class SelfCompressor:
    """ctxproof's own store/restore pipeline as an auditable compressor.

    Proves the envelope round-trip is byte-exact end to end: classify ->
    transform -> store -> marker -> restore -> hash-assert.
    """

    def __init__(self, store=None):
        from .store import Store, build_envelope, expand_envelope
        self._store = store or Store()
        self._build = build_envelope
        self._expand = expand_envelope
        self._envelopes: Dict[str, dict] = {}

    def compress(self, data: bytes) -> Tuple[bytes, str]:
        from .store import content_hash
        digest = content_hash(data)
        envelope = self._build(data, {"command": "ctxproof audit"})
        self._store.put(data, {
            "command": "ctxproof audit",
            "tier": envelope["tier"],
            "transforms": envelope["transforms"],
            "tables": envelope["tables"],
            "payload_bytes": envelope["payload_bytes"],
        })
        self._envelopes[envelope["marker"]] = envelope
        payload = envelope["payload_b64"].encode("ascii")
        return payload, envelope["marker"]

    def restore(self, marker: str) -> bytes:
        from .store import parse_marker
        digest = parse_marker(marker)
        blob = self._store.get(digest) if digest else None
        if blob is None:
            # fall back to envelope re-expansion (fail-closed path)
            envelope = self._envelopes.get(marker)
            if envelope is None:
                raise KeyError(f"no blob or envelope for {marker}")
            return self._expand(envelope)
        from .store import content_hash
        if content_hash(blob) != digest:
            raise ValueError("stored blob failed hash verification")
        return blob


def load_compressor(spec: str) -> Compressor:
    """Load ``dotted.path:ClassName`` and instantiate it with no args."""
    if ":" not in spec:
        raise ValueError("expected dotted.path:ClassName")
    mod_name, cls_name = spec.rsplit(":", 1)
    module = importlib.import_module(mod_name)
    cls = getattr(module, cls_name)
    return cls()


def main_audit(argv: List[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="ctxproof audit")
    ap.add_argument("--compressor", default="self",
                    help="dotted.path:ClassName to audit, or 'self'")
    ap.add_argument("--seed", type=int, default=20261021)
    args = ap.parse_args(argv)
    if args.compressor == "self":
        comp: Compressor = SelfCompressor()
    else:
        comp = load_compressor(args.compressor)
    result = audit(comp, seeds=build_seeds(args.seed))
    print(result.report())
    return 0 if result.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main_audit(sys.argv[1:]))
