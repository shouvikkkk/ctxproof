"""Audit harness tests: self-audit passes, naive lossy compressors are caught."""

import unittest

from ctxproof import audit as A


class NullCompressor:
    """Perfect compressor: stores bytes verbatim."""

    def __init__(self):
        self._blobs = {}

    def compress(self, data: bytes):
        marker = f"null://{len(self._blobs)}"
        self._blobs[marker] = data
        return data, marker

    def restore(self, marker: str):
        return self._blobs[marker]


class NaiveTruncatingCompressor:
    """Deliberately lossy: drops every line longer than 80 chars' tail.

    Simulates the headroom#4321 failure class — a compressor that mangles
    exact-text output on the wire.
    """

    def __init__(self):
        self._blobs = {}

    def compress(self, data: bytes):
        lines = data.split(b"\n")
        mangled = b"\n".join(
            l if len(l) <= 80 else l[:80] + b"..." for l in lines)
        marker = f"naive://{len(self._blobs)}"
        self._blobs[marker] = mangled
        return mangled, marker

    def restore(self, marker: str):
        return self._blobs[marker]


class AuditTestCase(unittest.TestCase):
    def test_null_compressor_passes(self):
        result = A.audit(NullCompressor())
        self.assertEqual(result.failed, 0)
        self.assertGreater(result.passed, 0)
        self.assertIn("passed", result.report())

    def test_naive_compressor_is_caught(self):
        result = A.audit(NaiveTruncatingCompressor())
        self.assertGreater(result.failed, 0)
        mangled = [s for s in result.seeds if not s.ok]
        self.assertTrue(mangled)
        # the report must say WHERE it diverged
        self.assertIn("divergence", mangled[0].detail)
        self.assertIn("MANGLED", result.report())

    def test_self_compressor_passes(self):
        import os
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        old = os.environ.get("CTXPROOF_HOME")
        os.environ["CTXPROOF_HOME"] = tmp.name
        try:
            result = A.audit(A.SelfCompressor())
        finally:
            if old is None:
                os.environ.pop("CTXPROOF_HOME", None)
            else:
                os.environ["CTXPROOF_HOME"] = old
            tmp.cleanup()
        self.assertEqual(result.failed, 0, result.report())

    def test_needles_present_in_seeds(self):
        seeds = A.build_seeds()
        needle_seeds = [s for s in seeds if "needle" in s[0]]
        self.assertTrue(needle_seeds)
        for _name, _kind, data in needle_seeds:
            self.assertIn(b"CTXPROOF-NEEDLE-", data)

    def test_load_compressor_dotted_path(self):
        comp = A.load_compressor("ctxproof.audit:SelfCompressor")
        self.assertIsInstance(comp, A.SelfCompressor)
        with self.assertRaises(ValueError):
            A.load_compressor("no-colon-here")

    def test_crashing_compressor_reported_not_raised(self):
        class Boom:
            def compress(self, data):
                raise RuntimeError("wire exploded")

            def restore(self, marker):
                raise RuntimeError("unreachable")

        result = A.audit(Boom(), seeds=[("s", "k", b"data")])
        self.assertEqual(result.failed, 1)
        self.assertIn("RuntimeError", result.seeds[0].detail)


if __name__ == "__main__":
    unittest.main()
