"""MYTHOS_WEB_AUDIT.md generation."""

from __future__ import annotations

from pathlib import Path

from ..ai.schema import SeverityEnum

_ORDER = list(SeverityEnum)


def render_web(data, report=None) -> str:
    """Raw scan results plus (optionally) the Gemini report."""
    out = [f"# Mythos Web Audit: {data.url}", ""]
    if report:
        out += [f"**Risk score:** {report.risk_score}/100", "", "## Executive Summary", report.executive_summary,
                "", "## Threat Narrative", report.threat_narrative, ""]
    out += ["## Scan Issues", "", "| Severity | Category | Issue | Detail |", "|---|---|---|---|"]
    out += [f"| {i.severity.value} | {i.category} | {i.title} | {i.detail} |" for i in data.issues]
    t = data.tls
    if t.checked:
        out += ["", "## TLS", f"{t.version} · {t.cipher} · issuer {t.issuer} · expires {t.not_after} ({t.days_left} days)"]
    out += ["", "## Security Headers", "", "| Header | Status | Note |", "|---|---|---|"]
    out += [f"| {h.name} | {h.status} | {h.note} |" for h in data.headers]
    if report:
        for f in sorted(report.findings, key=lambda f: _ORDER.index(f.severity)):
            out += ["", f"## {f.id} · {f.title} [{f.severity.value}]", f"{f.cwe_id} · {f.owasp} · confidence {f.confidence:.2f}",
                    "", f"**Evidence:** {f.evidence}", "", f"**Attack scenario:** {f.attack_scenario}", "",
                    f"**Impact:** {f.impact}", "", f"**Remediation:** {f.remediation}"]
            for c in f.configs:
                out += ["", f"**{c.platform}**", f"```{c.language}\n{c.snippet.strip()}\n```"]
        out += ["", "## Threat Model (STRIDE)", "", "| Category | Component | Threat | Risk | Mitigation |", "|---|---|---|---|---|"]
        out += [f"| {m.stride_category} | {m.component} | {m.threat} | {m.risk.value} | {m.mitigation} |" for m in report.threat_model]
    return "\n".join(out) + "\n"


def write_web_markdown(data, report, path: Path) -> None:
    path.write_text(render_web(data, report), encoding="utf-8")
