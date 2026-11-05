"""MYTHOS_AUDIT.md generation."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from ..ai.schema import MythosAuditReport, SeverityEnum

_ORDER = list(SeverityEnum)


def _fence(text: str, lang: str = "") -> str:
    return f"```{lang}\n{text.strip()}\n```"


def render(report: MythosAuditReport, secret_lines: list[str] | None = None) -> str:
    s = report.summary
    findings = sorted(report.findings, key=lambda f: (_ORDER.index(f.severity), -f.cvss_score))
    counts = Counter(f.severity for f in findings)
    out = [
        "# Mythos Security Audit",
        "",
        f"**Risk score:** {s.risk_score}/100 · **Stack:** {', '.join(s.detected_stack) or 'unknown'}",
        "",
        "## Executive Summary",
        s.executive_summary,
        "",
        "## Architecture Overview",
        s.architecture_overview,
        "",
        "## Findings Overview",
        "",
        "| Severity | Count |",
        "|---|---|",
        *[f"| {sev.value} | {counts.get(sev, 0)} |" for sev in _ORDER],
        "",
        "| ID | Severity | CVSS | CWE | Title | Location |",
        "|---|---|---|---|---|---|",
        *[
            f"| {f.id} | {f.severity.value} | {f.cvss_score:.1f} | {f.cwe_id} | {f.title} | `{f.file}:{f.start_line}` |"
            for f in findings
        ],
        "",
        "## Detailed Findings",
    ]
    for f in findings:
        out += [
            "",
            f"### {f.id}: {f.title}",
            "",
            f"- **Severity:** {f.severity.value} (CVSS {f.cvss_score:.1f}, `{f.cvss_vector}`)",
            f"- **CWE:** {f.cwe_id} · **OWASP:** {f.owasp} · **Confidence:** {f.confidence:.0%}",
            f"- **Location:** `{f.file}:{f.start_line}-{f.end_line}`",
            "",
            f.description,
            "",
            "**Taint flow (source → sink)**",
            "",
            *[
                f"{i}. **{st.role}** `{st.file}:{st.line}`: {st.description}\n   {_fence(st.code)}"
                for i, st in enumerate(f.taint_flow, 1)
            ],
            "",
            f"**Attack vector:** {f.attack_vector}",
            "",
            f"**Impact:** {f.impact}",
            "",
            f"**Remediation:** {f.remediation}",
            "",
            "**Proposed patch**",
            "",
            _fence(f.proposed_patch_diff, "diff"),
        ]
    out += ["", "## STRIDE Threat Model", "", "| Category | Component | Threat | Risk | Mitigation | Findings |", "|---|---|---|---|---|---|"]
    out += [
        f"| {t.stride_category} | {t.component} | {t.threat} | {t.risk.value} | {t.mitigation} | {', '.join(t.related_finding_ids) or '-'} |"
        for t in report.threat_model
    ]
    if s.positive_observations:
        out += ["", "## Positive Observations", *[f"- {p}" for p in s.positive_observations]]
    if secret_lines:
        out += ["", "## Secret Scanner Candidates (regex/entropy, unverified)", *[f"- {ln}" for ln in secret_lines]]
    return "\n".join(out) + "\n"


def write_markdown(report: MythosAuditReport, path: Path, secret_lines: list[str] | None = None) -> None:
    path.write_text(render(report, secret_lines), encoding="utf-8")
