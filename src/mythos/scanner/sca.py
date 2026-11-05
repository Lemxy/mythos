"""Dependency (SCA) scanning: pip-audit for Python, npm audit for Node.js."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from pydantic import BaseModel, Field

from ..ai.schema import SeverityEnum


class ScaVulnerability(BaseModel):
    ecosystem: str
    package: str
    version: str = ""
    id: str
    aliases: list[str] = Field(default_factory=list)
    severity: SeverityEnum = SeverityEnum.MEDIUM
    fix_versions: list[str] = Field(default_factory=list)
    summary: str = ""
    link: str = ""


class ScaResult(BaseModel):
    vulnerabilities: list[ScaVulnerability] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list, description="Tools skipped or failed")


def _run(cmd: list[str], cwd: Path, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def _link(vid: str, aliases: list[str]) -> str:
    for a in [vid, *aliases]:
        if a.startswith("GHSA-"):
            return f"https://github.com/advisories/{a}"
        if a.startswith("CVE-"):
            return f"https://nvd.nist.gov/vuln/detail/{a}"
    return f"https://osv.dev/vulnerability/{vid}"


def scan_python(root: Path, res: ScaResult) -> None:
    if (root / "requirements.txt").exists():
        target = ["-r", "requirements.txt"]
    elif (root / "pyproject.toml").exists():
        target = ["."]
    else:
        return
    try:
        p = _run([sys.executable, "-m", "pip_audit", "-f", "json", "--progress-spinner", "off", *target], root)
        deps = json.loads(p.stdout)["dependencies"]
    except (OSError, subprocess.TimeoutExpired) as exc:
        res.notes.append(f"pip-audit failed: {exc}")
        return
    except (ValueError, KeyError):
        res.notes.append(f"pip-audit gave unusable output (installed?): {(p.stderr or p.stdout)[-300:].strip()}")
        return
    for d in deps:
        for v in d.get("vulns", []):
            res.vulnerabilities.append(ScaVulnerability(
                ecosystem="PyPI", package=d["name"], version=d.get("version", ""), id=v["id"],
                aliases=v.get("aliases", []), fix_versions=v.get("fix_versions", []),
                summary=(v.get("description") or "")[:300], link=_link(v["id"], v.get("aliases", []))))


def scan_node(root: Path, res: ScaResult) -> None:
    if not (root / "package.json").exists():
        return
    npm = shutil.which("npm")
    if not npm:
        res.notes.append("package.json found but npm is not installed; skipped npm audit")
        return
    try:
        data = json.loads(_run([npm, "audit", "--json"], root).stdout)  # exits non-zero when vulns exist
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        res.notes.append(f"npm audit failed: {exc}")
        return
    if "error" in data:
        res.notes.append(f"npm audit error (a lockfile is required): {data['error'].get('summary', data['error'])}")
        return
    sev = {"critical": "CRITICAL", "high": "HIGH", "moderate": "MEDIUM", "low": "LOW", "info": "INFO"}
    for name, v in data.get("vulnerabilities", {}).items():
        advisories = [x for x in v.get("via", []) if isinstance(x, dict)]
        fix = v.get("fixAvailable")
        fixv = [f"{fix['name']}@{fix['version']}"] if isinstance(fix, dict) else []
        for a in advisories or [{}]:
            res.vulnerabilities.append(ScaVulnerability(
                ecosystem="npm", package=name, version=v.get("range", ""),
                id=str(a.get("source") or "indirect"),
                severity=SeverityEnum(sev.get(a.get("severity", v.get("severity")), "MEDIUM")),
                fix_versions=fixv, summary=a.get("title", "vulnerable via " + ", ".join(map(str, v.get("via", [])))),
                link=a.get("url", "")))


def scan_dependencies(root: Path) -> ScaResult:
    res = ScaResult()
    scan_python(root, res)
    scan_node(root, res)
    return res
