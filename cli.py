"""Command-line interface for ctxproof.

Commands:
  run      wrap a shell command, capturing raw stdout/stderr bytes
  store    classify + transform stdin/file bytes, print the envelope
  restore  re-hydrate original bytes from a marker (fail-closed)
  verify   check a marker's integrity against the store
  audit    differential corruption harness for any compressor
  stats    store statistics (bytes saved, dedup hits, est. tokens)
  gc       prune blobs older than N days

Exit codes: 0 ok · 1 hard failure · 2 served via fallback with a warning
(restore served the original bytes re-expanded from the envelope because
the stored blob was missing, expired, or tampered — never corrupted bytes).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from . import audit as audit_mod
from . import classifier as classifier_mod
from .store import (
    Store, build_envelope, capture_command, content_hash, expand_envelope,
    make_marker, parse_marker,
)

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_FALLBACK = 2  # served original bytes via envelope fallback + warning


def _warn(msg: str) -> None:
    print(f"ctxproof: warning: {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

def cmd_run(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(prog="ctxproof run",
                                 description="Run a command, capturing raw output bytes.")
    ap.add_argument("--envelope", action="store_true",
                    help="print the full envelope JSON for stdout instead of the run record")
    ap.add_argument("--ttl-days", type=float, default=None,
                    help="set a TTL on the stored blobs (retrieval markers expire)")
    ap.add_argument("command", nargs=argparse.REMAINDER,
                    help="command to run, after --")
    args = ap.parse_args(argv)
    if not args.command or args.command[0] == "--":
        cmd = [c for c in args.command if c != "--"]
    else:
        cmd = args.command
    if not cmd:
        print("ctxproof run: no command given (usage: ctxproof run -- <cmd>)",
              file=sys.stderr)
        return EXIT_FAIL

    store = Store()
    try:
        rec = capture_command(cmd)
        cmd_str = " ".join(cmd)
        meta_base = {
            "command": cmd_str,
            "exit_code": rec["exit_code"],
            "duration_ms": rec["duration_ms"],
            "captured_at": rec["captured_at"],
            "cwd": rec["cwd"],
        }
        out_digest, out_dd = store.put(rec["stdout"], {**meta_base, "stream": "stdout"})
        err_digest, err_dd = store.put(rec["stderr"], {**meta_base, "stream": "stderr"})
        if args.ttl_days is not None:
            store.set_expiry(out_digest, args.ttl_days)
            store.set_expiry(err_digest, args.ttl_days)
        if args.envelope:
            env = build_envelope(rec["stdout"], {**meta_base, "stream": "stdout"})
            # record the envelope's transform metadata on the row
            store.put(rec["stdout"], {
                **meta_base, "stream": "stdout",
                "tier": env["tier"], "risk": env["risk"],
                "reasons": env["reasons"], "transforms": env["transforms"],
                "tables": env["tables"], "payload_bytes": env["payload_bytes"],
            })
            print(json.dumps(env, indent=2))
        else:
            print(json.dumps({
                "stdout_marker": make_marker(out_digest),
                "stderr_marker": make_marker(err_digest),
                "stdout_deduped": out_dd,
                "stderr_deduped": err_dd,
                "exit_code": rec["exit_code"],
                "duration_ms": round(rec["duration_ms"], 1),
                "cwd": rec["cwd"],
            }, indent=2))
    finally:
        store.close()
    return EXIT_OK


# ---------------------------------------------------------------------------
# store
# ---------------------------------------------------------------------------

def cmd_store(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(prog="ctxproof store",
                                 description="Store bytes, print the envelope.")
    ap.add_argument("file", nargs="?", help="file to store (default: stdin)")
    ap.add_argument("--cmd", default="", help="command label for the classifier")
    ap.add_argument("--exit-code", type=int, default=0)
    ap.add_argument("--min-bytes", type=int, default=classifier_mod.DEFAULT_MIN_BYTES)
    ap.add_argument("--ttl-days", type=float, default=None)
    ap.add_argument("--persist", action="store_true",
                    help="also write the raw blob + envelope metadata to the store")
    args = ap.parse_args(argv)

    if args.file:
        data = Path(args.file).read_bytes()
    else:
        data = sys.stdin.buffer.read()
    meta = {"command": args.cmd, "exit_code": args.exit_code}
    env = build_envelope(data, meta, min_bytes=args.min_bytes)
    if args.persist:
        store = Store()
        try:
            digest = content_hash(data)
            store.put(data, {
                "command": args.cmd, "exit_code": args.exit_code,
                "tier": env["tier"], "risk": env["risk"],
                "reasons": env["reasons"], "transforms": env["transforms"],
                "tables": env["tables"], "payload_bytes": env["payload_bytes"],
            })
            if args.ttl_days is not None:
                store.set_expiry(digest, args.ttl_days)
        finally:
            store.close()
    print(json.dumps(env, indent=2))
    return EXIT_OK


# ---------------------------------------------------------------------------
# restore (fail-closed)
# ---------------------------------------------------------------------------

def _read_envelope(path: Optional[str]) -> Optional[dict]:
    if path:
        return json.loads(Path(path).read_text())
    if not sys.stdin.isatty():
        raw = sys.stdin.read()
        if raw.strip():
            return json.loads(raw)
    return None


def cmd_restore(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="ctxproof restore",
        description="Re-hydrate original bytes for a marker. Fail-closed: "
                    "missing/tampered blobs are never served as-is.")
    ap.add_argument("marker", help="ctxproof://blake2/<hex> marker")
    ap.add_argument("--envelope", default=None,
                    help="envelope JSON file (or stdin) for the fallback path")
    ap.add_argument("-o", "--output", default=None, help="write to file instead of stdout")
    args = ap.parse_args(argv)

    digest = parse_marker(args.marker)
    if digest is None:
        print(f"ctxproof restore: invalid marker: {args.marker}", file=sys.stderr)
        return EXIT_FAIL

    store = Store()
    try:
        row = store.lookup(digest)
        blob = store.get(digest)

        def emit(data: bytes) -> int:
            if args.output:
                Path(args.output).write_bytes(data)
            else:
                sys.stdout.buffer.write(data)
            return EXIT_OK

        # Happy path: blob present, fresh, hash-verified.
        if blob is not None and row is not None:
            expired = bool(row.get("expires_at")) and row["expires_at"] <= _now_iso()
            if not expired and content_hash(blob) == digest:
                return emit(blob)
            if expired:
                _warn(f"marker expired at {row['expires_at']} "
                      f"(headroom#4145 class bug: refusing stale cache); "
                      f"falling back to envelope re-expansion")
            elif content_hash(blob) != digest:
                _warn("stored blob FAILED hash verification (tampered or "
                      "corrupt); refusing to serve it")

        elif row is None:
            _warn("marker not found in this store")
        else:
            _warn("blob file missing from store (pruned?)")

        # Fallback: re-expand the envelope payload (byte-exact by construction).
        envelope = _read_envelope(args.envelope)
        if envelope is None:
            print("ctxproof restore: no envelope provided for fallback; "
                  "cannot serve unverified bytes", file=sys.stderr)
            return EXIT_FAIL
        try:
            original = expand_envelope(envelope)
        except ValueError as e:
            print(f"ctxproof restore: envelope fallback failed: {e}", file=sys.stderr)
            return EXIT_FAIL
        if parse_marker(envelope.get("marker", "")) != digest:
            print("ctxproof restore: envelope marker does not match requested marker",
                  file=sys.stderr)
            return EXIT_FAIL
        code = emit(original)
        _warn("served ORIGINAL bytes re-expanded from the envelope payload")
        return EXIT_FALLBACK if code == EXIT_OK else code
    finally:
        store.close()


def _now_iso() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

def cmd_verify(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(prog="ctxproof verify",
                                 description="Check a marker's integrity.")
    ap.add_argument("marker")
    args = ap.parse_args(argv)
    digest = parse_marker(args.marker)
    if digest is None:
        print("INVALID marker format", file=sys.stderr)
        return EXIT_FAIL
    store = Store()
    try:
        row = store.lookup(digest)
        if row is None:
            print("MISSING: no manifest entry for this marker")
            return EXIT_FAIL
        blob = store.get(digest)
        if blob is None:
            print("MISSING: manifest entry exists but blob file is gone (pruned?)")
            return EXIT_FAIL
        if content_hash(blob) != digest:
            print("TAMPERED: blob failed hash verification")
            return EXIT_FAIL
        if row.get("expires_at") and row["expires_at"] <= _now_iso():
            print(f"EXPIRED: marker expired at {row['expires_at']}")
            return EXIT_FAIL
        print(f"OK: {row['raw_bytes']} bytes, tier={row['tier']}, "
              f"hits={row['hits']}, captured {row['captured_at']}")
        return EXIT_OK
    finally:
        store.close()


# ---------------------------------------------------------------------------
# stats / gc
# ---------------------------------------------------------------------------

def cmd_stats(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(prog="ctxproof stats")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    store = Store()
    try:
        s = store.stats()
    finally:
        store.close()
    if args.json:
        print(json.dumps(s, indent=2))
        return EXIT_OK
    print(f"""ctxproof store stats
  captures:        {s['captures']}
  unique blobs:    {s['unique_blobs']}
  bytes stored:    {s['bytes_stored']}
  payload bytes:   {s['payload_bytes']}
  dedup hits:      {s['dedup_hits']} (rows with repeats: {s['rows_with_dedup']})
  bytes saved:     {s['bytes_saved']} (~{s['est_tokens_saved']} tokens @4B/tok)""")
    return EXIT_OK


def cmd_gc(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(prog="ctxproof gc",
                                 description="Prune blobs older than N days.")
    ap.add_argument("--ttl-days", type=float, required=True)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    store = Store()
    try:
        if args.dry_run:
            import datetime
            cutoff = (datetime.datetime.now(datetime.timezone.utc)
                      - datetime.timedelta(days=args.ttl_days)).isoformat()
            cur = store._conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(raw_bytes),0) FROM captures "
                "WHERE captured_at < ?", (cutoff,))
            n, b = cur.fetchone()
            print(f"would prune {n} blobs ({b} bytes) older than {args.ttl_days} days")
            return EXIT_OK
        blobs, rows = store.prune(args.ttl_days)
        print(f"pruned {blobs} blobs, {rows} manifest rows older than {args.ttl_days} days")
        return EXIT_OK
    finally:
        store.close()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ctxproof",
        description="Content-addressed integrity layer for tool output: "
                    "capture raw bytes, compress with a classifier, restore "
                    "byte-exact with hash verification.")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)
    for name, fn, help_ in [
        ("run", cmd_run, "run a command, capturing raw output bytes"),
        ("store", cmd_store, "classify+transform bytes, print the envelope"),
        ("restore", cmd_restore, "re-hydrate original bytes for a marker"),
        ("verify", cmd_verify, "check a marker's integrity"),
        ("audit", audit_mod.main_audit, "differential corruption harness"),
        ("stats", cmd_stats, "store statistics"),
        ("gc", cmd_gc, "prune old blobs"),
    ]:
        p = sub.add_parser(name, help=help_)
        p.set_defaults(_fn=fn)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    ap = build_parser()
    args, rest = ap.parse_known_args(argv)
    return args._fn(rest)


if __name__ == "__main__":
    sys.exit(main())
