"""Store tests: content addressing, dedup, fail-closed restore, TTL guard."""

import json
import os
import tempfile
import unittest

from ctxproof.store import (
    Store, build_envelope, content_hash, expand_envelope, make_marker,
    parse_marker,
)


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._old = os.environ.get("CTXPROOF_HOME")
        os.environ["CTXPROOF_HOME"] = self.tmp.name
        self.store = Store()

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()
        if self._old is None:
            os.environ.pop("CTXPROOF_HOME", None)
        else:
            os.environ["CTXPROOF_HOME"] = self._old

    # -- addressing -------------------------------------------------------
    def test_put_get_round_trip(self):
        data = b"hello world" * 100
        digest, deduped = self.store.put(data, {"command": "echo"})
        self.assertFalse(deduped)
        self.assertEqual(self.store.get(digest), data)
        self.assertEqual(content_hash(data), digest)

    def test_dedup_second_put(self):
        data = b"same bytes" * 200
        d1, dd1 = self.store.put(data, {"command": "run1"})
        d2, dd2 = self.store.put(data, {"command": "run2"})
        self.assertEqual(d1, d2)
        self.assertFalse(dd1)
        self.assertTrue(dd2)
        row = self.store.lookup(d1)
        self.assertEqual(row["hits"], 2)

    def test_binary_bytes_preserved(self):
        data = bytes(range(256)) * 10 + b"\xff\xfe binary \x00 stuff"
        digest, _ = self.store.put(data, {})
        self.assertEqual(self.store.get(digest), data)

    def test_marker_round_trip(self):
        digest = "ab" * 32
        marker = make_marker(digest)
        self.assertTrue(marker.startswith("ctxproof://blake2/"))
        self.assertEqual(parse_marker(marker), digest)
        self.assertIsNone(parse_marker("not a marker"))
        self.assertIsNone(parse_marker("ctxproof://blake2/short"))
        self.assertIsNone(parse_marker("ctxproof://sha256/" + digest))

    # -- envelope ---------------------------------------------------------
    def test_envelope_expand_round_trip(self):
        data = (b"2026-10-21 08:44:01 start\n" * 30
                + b"def f():\n    return 1\n" * 30)
        env = build_envelope(data, {"command": "run.sh", "exit_code": 0})
        self.assertTrue(env["marker"].startswith("ctxproof://blake2/"))
        self.assertEqual(expand_envelope(env), data)

    def test_expand_rejects_tampered_payload(self):
        data = b"A" * 600 + b"\n" + b"B" * 600
        env = build_envelope(data, {"command": "x"})
        import base64
        payload = bytearray(base64.b64decode(env["payload_b64"]))
        payload[10] ^= 0xFF
        env["payload_b64"] = base64.b64encode(bytes(payload)).decode()
        with self.assertRaises(ValueError):
            expand_envelope(env)

    def test_expand_rejects_bad_marker(self):
        env = build_envelope(b"z" * 600, {"command": "x"})
        env["marker"] = "ctxproof://blake2/" + "00" * 32
        with self.assertRaises(ValueError):
            expand_envelope(env)

    # -- TTL ---------------------------------------------------------------
    def test_ttl_expiry_guard(self):
        data = b"log line\n" * 100
        digest, _ = self.store.put(data, {"command": "tail"})
        self.assertTrue(self.store.set_expiry(digest, -1))  # already expired
        row = self.store.lookup(digest)
        self.assertIsNotNone(row["expires_at"])

    def test_prune_removes_old_blobs(self):
        data = b"old data" * 100
        digest, _ = self.store.put(data, {"command": "old"})
        # backdate the row
        self.store._conn.execute(
            "UPDATE captures SET captured_at = '2000-01-01T00:00:00+00:00' "
            "WHERE hash = ?", (digest,))
        self.store._conn.commit()
        blobs, rows = self.store.prune(30)
        self.assertEqual(blobs, 1)
        self.assertEqual(rows, 1)
        self.assertIsNone(self.store.get(digest))
        self.assertIsNone(self.store.lookup(digest))

    def test_stats_counts(self):
        d1 = b"aaa" * 300
        d2 = b"bbb" * 300
        self.store.put(d1, {"command": "c1"})
        self.store.put(d1, {"command": "c1"})  # dedup hit
        self.store.put(d2, {"command": "c2"})
        s = self.store.stats()
        self.assertEqual(s["unique_blobs"], 2)
        self.assertEqual(s["dedup_hits"], 1)
        self.assertEqual(s["bytes_stored"], len(d1) + len(d2))

    def test_missing_blob_returns_none(self):
        self.assertIsNone(self.store.get("ff" * 32))
        self.assertIsNone(self.store.lookup("ff" * 32))


if __name__ == "__main__":
    unittest.main()
