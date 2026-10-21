"""ctxproof — a content-addressed integrity layer for tool output.

Wrap any lossy context compressor with a verifiable byte-exact restoration
guarantee: capture raw tool-output bytes, fingerprint them (blake2b-256),
classify safe-to-compress risk, emit reversible compressed envelopes with
content-hash retrieval markers, and restore fail-closed with hash assertion.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
