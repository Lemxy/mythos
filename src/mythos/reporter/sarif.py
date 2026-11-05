"""SARIF v2.1.0 output."""

from __future__ import annotations

import json
from pathlib import Path

from .. import __version__
from ..ai.schema import MythosAuditReport, SeverityEnum

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {
    SeverityEnum.CRITICAL: "error", SeverityEnum.HIGH: "error", SeverityEnum.MEDIUM: "warning",
    SeverityEnum.LOW: "note", SeverityEnum.INFO: "note",
}


def _loc(file: str, start: int, end: int | None = None) -> dict:
    start = max(start, 1)
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": file.replace("\\", "/")},
            "region": {"startLine": start, "endLine": max(end or start, start)},
        }
    }


def to_sarif(report: MythosAuditReport) -> dict:
    rules, results = {}, []
    for f in report.findings:
        rules.setdefault(f.id, {
            "id": f.id,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description},
            "help": {"text": f.remediation},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe_id.removeprefix('CWE-')}.html",
            "properties": {"tags": ["security", f.cwe_id, f.owasp], "security-severity": f"{f.cvss_score:.1f}"},
        })
        result = {
            "ruleId": f.id,
            "level": _LEVEL[f.severity],
            "message": {"text": f"{f.title}: {f.description}"},
            "locations": [_loc(f.file, f.start_line, f.end_line)],
            "properties": {"severity": f.severity.value, "cvssVector": f.cvss_vector, "confidence": f.confidence},
        }
        if f.taint_flow:
            result["codeFlows"] = [{
                "threadFlows": [{
                    "locations": [
                        {"location": {**_loc(s.file, s.line), "message": {"text": f"[{s.role}] {s.description}"}}}
                        for s in f.taint_flow
                    ]
                }]
            }]
        results.append(result)
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Mythos", "version": __version__,
                "informationUri": "https://github.com/mythos/mythos", "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def write_sarif(report: MythosAuditReport, path: Path) -> None:
    path.write_text(json.dumps(to_sarif(report), indent=2), encoding="utf-8")
