"""End-to-end CLI tests via subprocess (isolated CTXPROOF_HOME)."""

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).parent.parent


def run_cli(*args, env_extra=None, stdin_bytes=None):
    env = dict(os.environ)
    env["CTXPROOF_HOME"] = env_extra["CTXPROOF_HOME"]
    # Always close stdin (b"" default): the CLI reads envelope JSON from
    # stdin when --envelope is omitted, and an inherited open stdin would
    # block forever waiting for input.
    return subprocess.run(
        [sys.executable, "-m", "ctxproof", *args],
        input=b"" if stdin_bytes is None else stdin_bytes,
        capture_output=True, env=env, cwd=str(REPO))


class CliTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = {"CTXPROOF_HOME": self.tmp.name}

    def tearDown(self):
        self.tmp.cleanup()

    def test_run_captures_bytes(self):
        p = run_cli("run", "--", "printf", "hello\\xff\\n", env_extra=self.env)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        rec = json.loads(p.stdout)
        self.assertTrue(rec["stdout_marker"].startswith("ctxproof://blake2/"))
        self.assertEqual(rec["exit_code"], 0)

    def test_run_records_exit_code(self):
        p = run_cli("run", "--", "sh", "-c", "exit 3", env_extra=self.env)
        rec = json.loads(p.stdout)
        self.assertEqual(rec["exit_code"], 3)

    def test_store_then_restore_round_trip(self):
        data = b"line one\nline one\nline one\nline two\n" * 50
        p = run_cli("store", "--cmd", "cat f", "--persist",
                    env_extra=self.env, stdin_bytes=data)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        env_doc = json.loads(p.stdout)
        marker = env_doc["marker"]
        p2 = run_cli("restore", marker, env_extra=self.env)
        self.assertEqual(p2.returncode, 0, p2.stderr.decode())
        self.assertEqual(p2.stdout, data)

    def test_restore_missing_marker_fails(self):
        p = run_cli("restore", "ctxproof://blake2/" + "ff" * 32,
                    env_extra=self.env)
        self.assertNotEqual(p.returncode, 0)

    def test_restore_tampered_blob_fails_closed(self):
        data = b"important exact bytes\n" * 100
        p = run_cli("store", "--cmd", "cat secret", "--persist",
                    env_extra=self.env, stdin_bytes=data)
        env_doc = json.loads(p.stdout)
        marker = env_doc["marker"]
        digest = marker.split("/")[-1]
        # tamper with the stored blob on disk
        blob = Path(self.tmp.name) / "store" / digest[:2] / digest[2:]
        raw = bytearray(blob.read_bytes())
        raw[5] ^= 0xFF
        blob.write_bytes(bytes(raw))
        # without envelope: must fail, must NOT emit the corrupted bytes
        p2 = run_cli("restore", marker, env_extra=self.env)
        self.assertNotEqual(p2.returncode, 0)
        self.assertNotIn(b"important exact", p2.stdout)
        self.assertIn(b"warning", p2.stderr.lower())
        # with envelope: serves the ORIGINAL bytes, warns, non-zero exit
        env_file = Path(self.tmp.name) / "env.json"
        env_file.write_text(json.dumps(env_doc))
        p3 = run_cli("restore", marker, "--envelope", str(env_file),
                     env_extra=self.env)
        self.assertEqual(p3.returncode, 2)
        self.assertEqual(p3.stdout, data)
        self.assertIn(b"warning", p3.stderr.lower())

    def test_restore_expired_marker_falls_back(self):
        data = b"2026-10-21 08:44:01 tick\n" * 100
        p = run_cli("store", "--cmd", "tail -f x", "--persist",
                    "--ttl-days", "-1",
                    env_extra=self.env, stdin_bytes=data)
        env_doc = json.loads(p.stdout)
        marker = env_doc["marker"]
        env_file = Path(self.tmp.name) / "env.json"
        env_file.write_text(json.dumps(env_doc))
        p2 = run_cli("restore", marker, "--envelope", str(env_file),
                     env_extra=self.env)
        # expired -> fallback to envelope re-expansion, original bytes, warn
        self.assertEqual(p2.returncode, 2, p2.stderr.decode())
        self.assertEqual(p2.stdout, data)

    def test_verify(self):
        data = b"verify me\n" * 100
        p = run_cli("store", "--cmd", "x", "--persist",
                    env_extra=self.env, stdin_bytes=data)
        marker = json.loads(p.stdout)["marker"]
        p2 = run_cli("verify", marker, env_extra=self.env)
        self.assertEqual(p2.returncode, 0)
        self.assertIn(b"OK", p2.stdout)
        p3 = run_cli("verify", "ctxproof://blake2/" + "00" * 32,
                     env_extra=self.env)
        self.assertNotEqual(p3.returncode, 0)
        self.assertIn(b"MISSING", p3.stdout)

    def test_stats_and_gc(self):
        p = run_cli("store", "--cmd", "x", "--persist",
                    env_extra=self.env, stdin_bytes=b"s" * 600)
        self.assertEqual(p.returncode, 0)
        p2 = run_cli("stats", env_extra=self.env)
        self.assertEqual(p2.returncode, 0)
        self.assertIn(b"captures:", p2.stdout)
        p3 = run_cli("gc", "--ttl-days", "0", "--dry-run", env_extra=self.env)
        self.assertEqual(p3.returncode, 0)
        self.assertIn(b"would prune", p3.stdout)

    def test_audit_self(self):
        p = run_cli("audit", "--compressor", "self", env_extra=self.env)
        self.assertEqual(p.returncode, 0, p.stdout.decode())
        self.assertIn(b"passed", p.stdout)


if __name__ == "__main__":
    unittest.main()
