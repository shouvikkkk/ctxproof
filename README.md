# ctxproof 🔏

**A content-addressed integrity layer for tool output.** Wrap *any* lossy context compressor with a verifiable, byte-exact restoration guarantee — so your coding agent never again reads mangled tool output and confidently acts on it.

## The problem

Lossy context compressors for coding agents silently mangle exact-text tool output. This isn't hypothetical — it's a real, open issue on a trending compressor:

**[headroomlabs-ai/headroom#4321](https://github.com/headroomlabs-ai/headroom/issues/4321)** (filed 2026-10-20):

> *"Models in Claude Code sessions routed through Headroom repeatedly say things like 'Compressor mangled the output; get line-exact context with grep.'"*

22 such model complaints across sessions from 2026-09-16 to 2026-10-20. The `log` strategy removes **>70% of content in over half its uses**. And the killer detail:

> *"Transcripts store the original tool result; compression happens on the wire, so what the model saw is not recoverable from them."*

A second real issue, **[#4145](https://github.com/headroomlabs-ai/headroom/issues/4145)**: expired retrieval markers return `"Content not found."` — the cache pretends to be an oracle and then lies.

The gap: **no existing compressor has a correctness oracle.** No content fingerprinting of raw tool results. No way to detect that compression corrupted a payload. No byte-exact restore. Compressors compress on heuristics and hope.

ctxproof is that oracle. It doesn't replace your compressor — it wraps it:

1. **Capture** raw tool-output *bytes* (not text — byte fidelity), with exit code, duration, cwd.
2. **Fingerprint** with blake2b-256 into a content-addressed store (repeat outputs dedupe — no re-compression cost on re-runs).
3. **Classify** safe-to-compress risk: exact-text content (source, diffs, JSON, test failures, stack traces) takes the lossless path; timestamped logs and banners take the aggressive path. Every transform is byte-exact reversible — "lossy" means *more aggressive*, never *lossy*.
4. **Emit** every compressed payload with a content-hash retrieval marker (`ctxproof://blake2/<hash>`).
5. **Restore fail-closed**: re-hydrate from the store and *assert* hash equality. Missing, expired, or tampered blob? Serve the original bytes re-expanded from the envelope with a warning — never the corrupted payload.
6. **Audit** any compressor: a differential harness seeds exact-text canaries through *your* compressor's `compress`/`restore` pair and reports exactly which payload classes get mangled.

## Install

Python 3.10+, no runtime dependencies (stdlib only: `hashlib`, `argparse`, `sqlite3`, `json`, `re`).

```bash
pip install .
# entry point: ctxproof
# or without installing:
python3 -m ctxproof --help
```

## Usage

**Capture a command's raw output bytes:**

```bash
ctxproof run -- pytest -x
# {
#   "stdout_marker": "ctxproof://blake2/9f2a…",
#   "stderr_marker": "ctxproof://blake2/41bc…",
#   "exit_code": 0,
#   "duration_ms": 412.3,
#   "cwd": "/home/user/proj"
# }
```

**Compress stdin/file bytes into an envelope (and persist it):**

```bash
cat app.log | ctxproof store --cmd "tail -f app.log" --persist
# {
#   "format": "ctxproof/envelope-1",
#   "marker": "ctxproof://blake2/9f2a…",
#   "tier": "lossy",
#   "risk": 0.2,
#   "reasons": ["timestamped log lines (100%)"],
#   "transforms": ["line-run-dedup", "timestamp-collapse", ...],
#   "payload_b64": "…",
#   "raw_bytes": 3940,
#   "payload_bytes": 170
# }
```

**Restore byte-exact (fail-closed):**

```bash
ctxproof restore "ctxproof://blake2/9f2a…" > original.log
ctxproof verify "ctxproof://blake2/9f2a…"   # OK / MISSING / TAMPERED / EXPIRED
```

If the stored blob is missing, expired, or fails hash verification, `restore` refuses to serve it. Hand it the envelope and it re-expands the payload (byte-exact by construction), warns on stderr, and exits `2`:

```bash
ctxproof restore "$MARKER" --envelope envelope.json > original.log
# ctxproof: warning: stored blob FAILED hash verification (tampered or corrupt); refusing to serve it
# ctxproof: warning: served ORIGINAL bytes re-expanded from the envelope payload
# exit code: 2
```

**Audit any compressor** (implements `compress(bytes) -> (payload, marker)` / `restore(marker) -> bytes`):

```bash
ctxproof audit --compressor mypkg.compressors:NaiveCompressor
# ctxproof audit — NaiveCompressor
# SEED                              KIND            SIZE  STATUS  DETAIL
# long-json-line                    long-line        402  MANGLED first divergence at byte 80 ...
# ─────────────────────────────────────────────────────────────
# 18 passed, 2 mangled out of 20 seeds

ctxproof audit --compressor self   # audit ctxproof's own pipeline end-to-end
```

**Housekeeping:**

```bash
ctxproof stats                        # captures, dedup hits, bytes/tokens saved
ctxproof gc --ttl-days 30 --dry-run   # prune blobs older than 30 days
```

## How the marker protocol works

```
 raw bytes ──blake2b-256──▶ digest ──▶ marker  ctxproof://blake2/<64 hex>
     │                                          │
     │ classify (risk tier)                     │ travels in the prompt
     │ transform (reversible)                   │ instead of raw output
     ▼                                          ▼
 envelope { marker, tier, transforms,   ctxproof restore <marker>
            tables, payload_b64 }         1. look up digest in manifest
                                          2. blob exists? hash(blob) == digest?
                                          3. not expired?  ──▶ serve blob bytes
                                          4. else: warn + re-expand envelope
                                             payload, assert hash, serve with
                                             warning (exit 2) — or fail (exit 1)
```

The store lives at `~/.ctxproof/` (override with `CTXPROOF_HOME`): blobs under `store/<aa>/<bb…>` (git-style fan-out), metadata in `manifest.sqlite`. Identical outputs dedupe to one blob — re-running a command costs nothing.

**Transforms** (all declare `lossless: true` and round-trip on arbitrary bytes, including binary):

| Transform | Tier | What it does |
|---|---|---|
| `line-run-dedup` | lossless | collapses runs of ≥3 identical lines into `count + line` |
| `timestamp-collapse` | lossy | `2026-10-21 08:44:01` → microsecond delta from payload base (integer arithmetic — no float drift) |
| `repeated-block-fold` | lossy | folds repeated multi-line blocks (banners) into references |
| `whitespace-collapse` | lossy | collapses leading runs of ≥8 spaces/tabs |

Markers use a `\x1f`-sentinel scheme with global escaping, so they can never collide with payload content. The classifier is a documented heuristic (`ctxproof/classifier.py`): file-reading commands, diff markers, JSON parse, line-number ratios, stack-trace and test-failure signatures push toward lossless; timestamped/progress/build-step lines push toward lossy; sub-512-byte and binary payloads bypass transforms entirely.

## Differentiation

- **vs headroom** (and similar lossy compressors): they compress on heuristics with no integrity story — nothing fingerprints the raw tool result, nothing detects corruption, expired markers return "Content not found." ctxproof adds the missing layer: content addressing, hash-verified restore, TTL-expiry guards, and a differential audit harness. It wraps your compressor; it doesn't ask you to replace it.
- **vs mksglu/context-mode** (claims ~98% context reduction): reduction claims without a corruption detector are exactly the failure mode in headroom#4321. ctxproof's `audit` command is the falsifiable check those claims lack — run it against any compressor and see which payload classes survive byte-exact.

## Honest limitations

- **The classifier is heuristic, not learned.** It is tuned conservative by design: false positives (calling a log "lossless") cost bytes; false negatives (calling source code "lossy") would cost correctness — the test suite asserts exact-text recall is 100% on the fixture corpus. Exotic languages and formats it hasn't seen can surprise it; add fixtures in `tests/fixtures/` and re-run.
- **The bash wrapper captures only what it wraps.** It can't see compression that happens on the wire *inside* a harness (the exact headroom#4321 scenario) — for that, integrate at the harness level: store raw tool results via the `Store` API *before* handing them to the compressor, and restore from markers after.
- **Local, single-machine store.** Markers are only resolvable where the store lives (`~/.ctxproof`, or a shared `CTXPROOF_HOME`). There is no network replication — by design, for now.
- **Timestamp collapse covers common log formats only** (`YYYY-MM-DD[ T]HH:MM:SS` with optional fraction, no timezone suffix). Anything else passes through untouched.
- **Audit seeds are a fixed corpus**, not adversarial generation. A compressor that passes can still mangle inputs outside the corpus — extend `SEEDS` in `ctxproof/audit.py` for your domain.

## Tests

```bash
python3 -m unittest discover -s tests   # 45 tests, zero dependencies
# pytest tests/ -q                      # optional, nicer output
```

Covers: transform round-trips on a seeded fuzz corpus (binary, non-UTF8, sentinel collisions), classifier precision/recall on 16 real fixtures, dedup, tamper fail-closed restore, TTL-expiry fallback, and the audit harness catching a deliberately lossy compressor.

## License

MIT — see [LICENSE](LICENSE).
