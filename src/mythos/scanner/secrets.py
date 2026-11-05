"""Fast regex + Shannon entropy scanner for hard-coded credentials."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

PATTERNS: dict[str, re.Pattern[str]] = {
    "AWS Access Key ID": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "AWS Secret Access Key": re.compile(r"(?i)aws.{0,20}(?:secret|key).{0,5}['\"=:\s]+([A-Za-z0-9/+=]{40})\b"),
    "GitHub Token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "Slack Token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "Stripe Secret Key": re.compile(r"\b[sr]k_live_[0-9A-Za-z]{24,}\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "Private Key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    "Database URL with credentials": re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@'\"]+:[^\s@'\"]+@[^\s'\"]+"
    ),
}
# generic `secret = "high-entropy"` assignments
_ASSIGN = re.compile(
    r"""(?ix)(?:password|passwd|secret|token|api[_-]?key|auth)\w*\s*[:=]\s*['"]([^'"\s]{12,})['"]"""
)
_PLACEHOLDER = re.compile(r"(?i)example|changeme|your[_-]|xxx|placeholder|<.*>|\$\{|\{\{|dummy|test")
ENTROPY_THRESHOLD = 4.0


@dataclass(frozen=True)
class SecretHit:
    file: str
    line: int
    kind: str
    redacted: str


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _redact(s: str) -> str:
    return s[:4] + "****" if len(s) > 8 else "*" * len(s)


def scan_text(file: str, text: str) -> list[SecretHit]:
    """Scan one file's text; matches are redacted so reports never leak the secret."""
    hits: list[SecretHit] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000:  # minified blobs: too slow and too noisy
            continue
        matched = False
        for kind, pat in PATTERNS.items():
            if m := pat.search(line):
                hits.append(SecretHit(file, lineno, kind, _redact(m.group(0))))
                matched = True
        if matched:
            continue
        if (m := _ASSIGN.search(line)) and not _PLACEHOLDER.search(m.group(1)):
            if shannon_entropy(m.group(1)) >= ENTROPY_THRESHOLD:
                hits.append(SecretHit(file, lineno, "High-entropy secret assignment", _redact(m.group(1))))
    return hits


def scan_packed(packed: str) -> list[SecretHit]:
    """Scan packer output (``=== FILE: x (n lines) ===`` blocks with ``N| `` prefixes)."""
    hits: list[SecretHit] = []
    for block in re.split(r"^=== FILE: ", packed, flags=re.M)[1:]:
        header, _, body = block.partition("\n")
        name = header.rsplit(" (", 1)[0]
        stripped = "\n".join(ln.split("| ", 1)[-1] for ln in body.splitlines())
        hits.extend(scan_text(name, stripped))
    return hits
