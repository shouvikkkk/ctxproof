"""Safe-to-compress risk classifier for ctxproof.

Decides, per captured tool output, which compression tier is safe:

* ``lossless``   — exact-text content (source code, diffs, JSON, test
  failures, stack traces, line-numbered output). Only reversible marker
  transforms are applied; the payload stays structurally identical.
* ``lossy``      — safe-to-shrink content (timestamped logs, repeated CLI
  banners, progress output). All transforms may be applied — still
  byte-exact reversible, just more aggressive.
* ``passthrough``— below the size floor, or binary: stored content-addressed
  (dedup still applies) but no transform touches it.

The classifier is a documented, testable heuristic — not ML. It is tuned
**conservative by design**: exact-text recall must be 100% (never compress
exact content aggressively); false positives on safe content (calling a log
"lossless") only cost bytes, never correctness.

``classify(command, data)`` returns a :class:`Verdict` with the tier, a
0..1 risk score, and human-readable reasons (surfaced in the envelope and
in ``ctxproof stats``).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import List, Tuple

__all__ = ["Verdict", "classify", "DEFAULT_MIN_BYTES", "RISK_THRESHOLD"]

DEFAULT_MIN_BYTES = 512  # never transform payloads smaller than this
RISK_THRESHOLD = 0.5     # risk >= threshold -> lossless tier


@dataclass
class Verdict:
    tier: str                      # "lossless" | "lossy" | "passthrough"
    risk: float                    # 0..1 — higher = more exact-text risk
    reasons: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Signal patterns
# ---------------------------------------------------------------------------

# Commands whose output is definitionally exact text: file readers, VCS show.
_FILE_READ_CMDS = re.compile(
    r"(?<![\w-])(cat|bat|less|more|head|tail|sed(?:\s+-n)?|awk|nl|tac|"
    r"git\s+(show|diff|log\s+-[p]|blame)|hg\s+(cat|diff)|"
    r"xxd|hexdump|od|strings)(?![\w-])"
)

_DIFF_MARKERS = re.compile(r"^(diff --git|@@ |--- |\+\+\+ )", re.MULTILINE)
_LINE_NUMBERED = re.compile(r"^\s*\d+\s*[:|│]\s+\S", re.MULTILINE)
_STACK_TRACE = re.compile(
    r"Traceback \(most recent call last\)"
    r"|^\s*File \"[^\"]+\", line \d+"
    r"|\bat\s+[\w.$]+\([\w.$]+:\d+\)"
    r"|\b(panic|fatal error):",
    re.MULTILINE,
)
# NOTE: bare "^ERROR" is deliberately NOT a test-failure signal — log-level
# ERROR lines belong to timestamped logs (handled by the safe signal below).
# Test failures are caught by FAILED / AssertionError / pytest's "E" indent /
# summary lines like "1 failed, 23 passed".
_TEST_FAILURE = re.compile(
    r"^FAILED\s+\S|AssertionError|"
    r"^E\s{2,}\S|test.*\bFAILED\b|^\d+\s+failed[,.]",
    re.MULTILINE,
)
_CODE_KEYWORDS = re.compile(
    r"\b(def |class |import |from |return |function |const |let |var |"
    r"fn |package |func |SELECT |FROM |WHERE |INSERT |UPDATE |"
    r"#include|public |private |interface |struct |impl |match |=>)\b"
)
_TIMESTAMPED_LINE = re.compile(
    r"^\s*\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"|^\s*\d{2}:\d{2}:\d{2}([.,]\d+)?\s"
    r"|^\s*(INFO|DEBUG|WARN|WARNING|ERROR|TRACE)\b",
    re.MULTILINE,
)
_PROGRESS_LINE = re.compile(
    r"\d+\s*%|\b(it|MB|kB)/s\b|Downloading|Downloaded| eta ",
    re.IGNORECASE,
)
_BUILD_STEP = re.compile(r"^\s*=>|Step \d+/\d+|^\s*#\d+ \S", re.MULTILINE)
_PKG_MGR = re.compile(
    r"^(Get:|Reading|Building|Selecting|Preparing|Unpacking|Setting up)\b",
    re.MULTILINE,
)


def _ratio(pattern: re.Pattern, lines: List[str]) -> float:
    if not lines:
        return 0.0
    return sum(1 for l in lines if pattern.search(l)) / len(lines)


def _looks_like_json(text: str) -> bool:
    stripped = text.strip()
    if len(stripped) < 2 or stripped[0] not in "{[":
        return False
    try:
        json.loads(stripped)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def classify(command: str, data: bytes,
             min_bytes: int = DEFAULT_MIN_BYTES) -> Verdict:
    """Score ``data`` (raw bytes from ``command``) and pick a tier."""
    reasons: List[str] = []
    risk = 0.5  # start neutral; evidence moves it

    # --- hard floors ------------------------------------------------------
    if len(data) < min_bytes:
        return Verdict("passthrough", 0.0,
                       [f"below {min_bytes}-byte compression floor"])
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return Verdict("passthrough", 0.0, ["non-UTF8 binary content"])
    lines = text.splitlines()
    if not lines:
        return Verdict("passthrough", 0.0, ["empty output"])

    def bump(delta: float, reason: str) -> None:
        nonlocal risk
        risk += delta
        reasons.append(reason)

    # --- exact-text evidence (push toward lossless) ------------------------
    if _FILE_READ_CMDS.search(command or ""):
        bump(0.35, f"file-reading command: {command.split()[0] if command else '?'}")
    if _DIFF_MARKERS.search(text):
        bump(0.50, "unified diff markers (diff --git / @@ / --- / +++)")
    if _looks_like_json(text):
        bump(0.50, "payload parses as JSON")
    ln_ratio = _ratio(_LINE_NUMBERED, lines)
    if ln_ratio >= 0.25:
        bump(0.40, f"line-numbered output ({ln_ratio:.0%} of lines)")
    if _STACK_TRACE.search(text):
        bump(0.45, "stack trace / panic signature")
    if _TEST_FAILURE.search(text):
        bump(0.40, "test failure signature")
    code_hits = len(_CODE_KEYWORDS.findall(text))
    code_density = code_hits / max(len(lines), 1)
    brace_density = (text.count("{") + text.count("}") + text.count(";")) / max(len(text), 1)
    if code_density >= 0.30 or (brace_density >= 0.02 and code_density >= 0.10):
        bump(0.35, f"code-like syntax (keyword density {code_density:.2f}/line)")

    # --- safe-to-shrink evidence (push toward lossy) -----------------------
    ts_ratio = _ratio(_TIMESTAMPED_LINE, lines)
    if ts_ratio >= 0.40:
        bump(-0.30, f"timestamped log lines ({ts_ratio:.0%})")
    prog_ratio = _ratio(_PROGRESS_LINE, lines)
    if prog_ratio >= 0.15:
        bump(-0.20, "download/progress output")
    if _ratio(_BUILD_STEP, lines) >= 0.25:
        bump(-0.20, "container build-step output")
    if _ratio(_PKG_MGR, lines) >= 0.25:
        bump(-0.15, "package-manager chatter")
    # repeated banner: the same non-empty line appearing 3+ times
    seen: dict = {}
    for l in lines:
        s = l.strip()
        if s:
            seen[s] = seen.get(s, 0) + 1
    if any(c >= 3 for c in seen.values()):
        bump(-0.15, "repeated banner/boilerplate lines")

    risk = max(0.0, min(1.0, risk))
    tier = "lossless" if risk >= RISK_THRESHOLD else "lossy"
    if not reasons:
        reasons.append("no strong signal either way; defaulting conservative")
        tier = "lossless"
        risk = max(risk, RISK_THRESHOLD)
    return Verdict(tier, risk, reasons)
