"""Pydantic models for the structured audit report (also the Gemini response schema)."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class SeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class TaintStep(BaseModel):
    role: str = Field(description="One of: source, propagation, sanitizer, sink")
    file: str = Field(description="Repo-relative file path, exactly as in the packed input")
    line: int = Field(description="1-based line number from the packed input")
    code: str = Field(description="The relevant code snippet on that line")
    description: str = Field(description="What happens to the tainted data here")


class VulnerabilityFinding(BaseModel):
    id: str = Field(description="Stable ID such as MYTHOS-001")
    title: str
    severity: SeverityEnum
    confidence: float = Field(description="0.0-1.0 confidence that this is a true positive")
    cwe_id: str = Field(description="e.g. CWE-89")
    owasp: str = Field(description="e.g. A03:2021-Injection")
    cvss_score: float = Field(description="CVSS v3.1 base score 0.0-10.0")
    cvss_vector: str = Field(description="e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    file: str = Field(description="Primary file of the vulnerable sink")
    start_line: int
    end_line: int
    description: str
    taint_flow: list[TaintStep] = Field(description="Ordered source-to-sink data flow")
    attack_vector: str = Field(description="Concrete exploitation scenario with example payload")
    impact: str
    remediation: str
    proposed_patch_diff: str = Field(description="Unified diff that fixes the issue")


class ThreatModelItem(BaseModel):
    stride_category: str = Field(
        description="Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, or Elevation of Privilege"
    )
    component: str
    threat: str
    risk: SeverityEnum
    mitigation: str
    related_finding_ids: list[str]


class AuditSummary(BaseModel):
    executive_summary: str
    architecture_overview: str
    detected_stack: list[str]
    risk_score: int = Field(description="Overall risk 0 (safe) to 100 (critical)")
    positive_observations: list[str]


class MythosAuditReport(BaseModel):
    summary: AuditSummary
    findings: list[VulnerabilityFinding]
    threat_model: list[ThreatModelItem]


class ConfigSnippet(BaseModel):
    platform: str = Field(description="One of: Nginx, Apache, Caddy, Cloudflare, Express/Helmet.js")
    language: str = Field(description="Code fence language, e.g. nginx, apache, caddyfile, js")
    snippet: str = Field(description="Exact, copy-pasteable server configuration")


class WebFinding(BaseModel):
    id: str = Field(description="Stable ID such as WEB-001")
    title: str
    severity: SeverityEnum
    confidence: float = Field(description="0.0-1.0")
    cwe_id: str
    owasp: str
    evidence: str = Field(description="The observed header/cookie/response from the scan data that proves it")
    attack_scenario: str = Field(
        description="Concrete attack: Clickjacking, CSRF, DOM XSS, CORS credential theft, session hijacking, etc."
    )
    impact: str
    remediation: str
    configs: list[ConfigSnippet] = Field(description="Server fixes for each relevant platform")


class WebAuditReport(BaseModel):
    executive_summary: str
    threat_narrative: str = Field(description="How an attacker would chain the weaknesses end to end")
    risk_score: int = Field(description="0 (safe) to 100 (critical)")
    findings: list[WebFinding]
    threat_model: list[ThreatModelItem]
    positive_observations: list[str]
