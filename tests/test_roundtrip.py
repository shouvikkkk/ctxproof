"""Transform round-trip tests: revert(apply(x)) == x for every transform.

Includes a seeded fuzz corpus with binary, non-UTF8, sentinel bytes, and
empty inputs. Every registered transform must also declare lossless=True.
"""

import random
import unittest
from pathlib import Path

from ctxproof import transforms as T

FIXTURES = Path(__file__).parent / "fixtures"


def fuzz_corpus(n=300, seed=20261021):
    rng = random.Random(seed)
    out = []
    # random bytes incl. non-UTF8, NULs, sentinel bytes
    for _ in range(n):
        length = rng.choice([0, 1, 7, 64, 300, 2000])
        out.append(bytes(rng.randrange(256) for _ in range(length)))
    # text with timestamps, runs, whitespace, sentinel collisions
    for _ in range(n // 3):
        lines = []
        for _ in range(rng.randrange(1, 40)):
            kind = rng.randrange(6)
            if kind == 0:
                lines.append(
                    f"2026-10-{rng.randrange(1,28):02d} "
                    f"{rng.randrange(24):02d}:{rng.randrange(60):02d}:"
                    f"{rng.randrange(60):02d} event {rng.randrange(5)}"
                )
            elif kind == 1:
                lines.append("same line repeated")  # run fodder
            elif kind == 2:
                lines.append("        deeply indented code();")
            elif kind == 3:
                lines.append("plain log line number %d" % rng.randrange(100))
            elif kind == 4:
                lines.append("\x1fCTXPROOF\x1fFAKE\x1fmarker-like\x1f")
            else:
                lines.append("")
        out.append("\n".join(lines).encode("utf-8", "ignore"))
    # fixture files themselves
    for f in FIXTURES.glob("*"):
        if f.is_file():
            out.append(f.read_bytes())
    return out


class TestTransformProperties(unittest.TestCase):
    def test_all_declare_lossless(self):
        for name, t in T.TRANSFORMS.items():
            self.assertTrue(t.lossless, f"{name} must declare lossless=True")

    def test_each_transform_round_trips_fuzz(self):
        corpus = fuzz_corpus()
        for name, t in T.TRANSFORMS.items():
            for i, blob in enumerate(corpus):
                enc, tables = t.encode(blob)
                try:
                    dec = t.decode(enc, tables)
                except T.TransformError as e:
                    self.fail(f"{name}: decode failed on fuzz sample {i}: {e}")
                self.assertEqual(
                    dec, blob,
                    f"{name}: round-trip mismatch on fuzz sample {i} "
                    f"(len {len(blob)})")

    def test_tier_pipeline_round_trips_fuzz(self):
        corpus = fuzz_corpus(n=120)
        for tier in ("lossless", "lossy", "passthrough"):
            for i, blob in enumerate(corpus):
                enc, tables = T.apply(blob, tier)
                dec = T.revert(enc, tier, tables)
                self.assertEqual(dec, blob,
                                 f"tier {tier}: mismatch on sample {i}")

    def test_sentinel_collision_is_safe(self):
        evil = b"\x1fCTXPROOF\x1fRUN\x1f99\x1f\nreal line\n\x1f lone sentinel"
        for tier in ("lossless", "lossy"):
            enc, tables = T.apply(evil, tier)
            self.assertEqual(T.revert(enc, tier, tables), evil)

    def test_empty_and_tiny_inputs(self):
        for blob in (b"", b"\n", b"x", b"\x1f", b"\xff\xfe"):
            for tier in ("lossless", "lossy", "passthrough"):
                enc, tables = T.apply(blob, tier)
                self.assertEqual(T.revert(enc, tier, tables), blob)

    def test_unknown_tier_raises(self):
        with self.assertRaises(T.TransformError):
            T.apply(b"x", "nope")
        with self.assertRaises(T.TransformError):
            T.revert(b"x", "nope", {})

    def test_missing_table_fails_closed(self):
        data = b"2026-10-21 08:44:01 hello\n2026-10-21 08:44:02 world\n"
        enc, _tables = T.TRANSFORMS["timestamp-collapse"].encode(data)
        self.assertIn(b"CTXPROOF", enc)  # tokens were actually inserted
        with self.assertRaises(T.TransformError):
            T.TRANSFORMS["timestamp-collapse"].decode(enc, {})
        # ...but clean data with empty tables is still the identity
        clean = b"no timestamps here\n"
        enc2, t2 = T.TRANSFORMS["timestamp-collapse"].encode(clean)
        self.assertEqual(enc2, clean)
        self.assertEqual(T.TRANSFORMS["timestamp-collapse"].decode(enc2, t2), clean)

    def test_timestamp_fractional_precision(self):
        data = b"2026-10-21 08:44:01.5 a\n2026-10-21 08:44:01.500 b\n2026-10-21T08:44:02 c\n"
        t = T.TRANSFORMS["timestamp-collapse"]
        enc, tables = t.encode(data)
        self.assertEqual(t.decode(enc, tables), data)

    def test_repeated_block_fold_round_trip(self):
        block = b"==== banner ====\ndeploy v1\n"
        data = b"start\n" + block * 4 + b"middle\n" + block * 2 + b"end\n"
        t = T.TRANSFORMS["repeated-block-fold"]
        enc, tables = t.encode(data)
        self.assertIn(b"CTXPROOF", enc)
        self.assertEqual(t.decode(enc, tables), data)


if __name__ == "__main__":
    unittest.main()
