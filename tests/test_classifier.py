"""Classifier tests.

The hard guarantee: exact-text content must NEVER be classified "lossy".
The classifier may be conservative (calling safe content "lossless") but it
must never be aggressive (calling exact content "lossy").
"""

import unittest
from pathlib import Path

from ctxproof.classifier import DEFAULT_MIN_BYTES, classify

FIXTURES = Path(__file__).parent / "fixtures"

# (fixture, command label) — exact-text content, recall must be 100%
EXACT = [
    ("pytest-failure.txt", "pytest -x"),
    ("json-blob.txt", "curl -s localhost:8080/run"),
    ("cat-n-source.txt", "cat -n app.py"),
    ("unified-diff.txt", "git diff"),
    ("stack-trace.txt", "python worker.py"),
    ("git-show-file.txt", "git show HEAD:store.py"),
    ("sed-range.txt", "sed -n '1,20p' svc.conf"),
    ("tsc-errors.txt", "tsc --noEmit"),
]

# safe content where the lossy tier is preferred (lossless also acceptable)
SAFE_LOSSY = [
    "server-log.txt",
    "pip-install.txt",
    "docker-build.txt",
    "apt-get.txt",
    "ascii-banner.txt",
]


class TestClassifier(unittest.TestCase):
    def test_exact_text_recall_is_100_percent(self):
        for fname, cmd in EXACT:
            data = (FIXTURES / fname).read_bytes()
            v = classify(cmd, data)
            self.assertNotEqual(
                v.tier, "lossy",
                f"{fname}: exact-text content classified lossy — "
                f"aggressive misclassification (risk={v.risk})")
            self.assertIn(v.tier, ("lossless", "passthrough"))

    def test_exact_text_above_floor_is_lossless(self):
        for fname, cmd in EXACT:
            data = (FIXTURES / fname).read_bytes()
            self.assertGreater(len(data), DEFAULT_MIN_BYTES,
                               f"{fname} fixture should exceed the compression floor")
            v = classify(cmd, data)
            self.assertEqual(v.tier, "lossless", f"{fname}: {v.reasons}")

    def test_safe_content_prefers_lossy(self):
        for fname in SAFE_LOSSY:
            data = (FIXTURES / fname).read_bytes()
            v = classify("", data)
            self.assertEqual(v.tier, "lossy", f"{fname}: {v.reasons}")

    def test_below_floor_is_passthrough(self):
        v = classify("cat big.py", b"x" * (DEFAULT_MIN_BYTES - 1))
        self.assertEqual(v.tier, "passthrough")

    def test_binary_is_passthrough(self):
        v = classify("", bytes(range(256)) * 4)
        self.assertEqual(v.tier, "passthrough")
        self.assertIn("binary", v.reasons[0].lower())

    def test_empty_is_passthrough(self):
        self.assertEqual(classify("", b"").tier, "passthrough")

    def test_file_reading_command_boosts_lossless(self):
        code = b"def f():\n    return 1\n" * 40  # 640B of code, weak signals
        v = classify("cat f.py", code)
        self.assertEqual(v.tier, "lossless")

    def test_reasons_always_present(self):
        for fname, cmd in EXACT:
            v = classify(cmd, (FIXTURES / fname).read_bytes())
            self.assertTrue(v.reasons, f"{fname}: no reasons recorded")

    def test_risk_is_bounded(self):
        for fname, cmd in EXACT:
            v = classify(cmd, (FIXTURES / fname).read_bytes())
            self.assertGreaterEqual(v.risk, 0.0)
            self.assertLessEqual(v.risk, 1.0)

    def test_config_floor_is_honored(self):
        data = b"log line\n" * 100  # 900B of safe content
        self.assertEqual(classify("", data, min_bytes=4096).tier, "passthrough")
        self.assertEqual(classify("", data, min_bytes=64).tier, "lossy")


if __name__ == "__main__":
    unittest.main()
