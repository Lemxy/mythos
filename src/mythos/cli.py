"""Mythos command line interface."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .ai.gemini_client import DEFAULT_MODEL, GeminiError, GeminiQuotaError, run_audit, run_web_audit
from .ai.schema import MythosAuditReport, SeverityEnum
from .config import MissingApiKeyError, ensure_gemini_api_key, get_gemini_api_key
from .reporter.markdown import write_markdown
from .reporter.sarif import write_sarif
from .scanner.deep import scan_deep
from .scanner.packer import pack_codebase
from .reporter.web_markdown import write_web_markdown
from .scanner.sca import scan_dependencies
from .scanner.secrets import scan_packed
from .scanner.web import audit_web

app = typer.Typer(help="Mythos: AI-assisted security audit & threat modeling.", no_args_is_help=True)
console = Console()

_STYLE = {
    SeverityEnum.CRITICAL: "bold red", SeverityEnum.HIGH: "red", SeverityEnum.MEDIUM: "yellow",
    SeverityEnum.LOW: "cyan", SeverityEnum.INFO: "dim",
}
REPORT_JSON = ".mythos/report.json"
PACKED_JSON = ".mythos/packed_for_claude.json"
EXIT_CODE_FALLBACK_TO_CLAUDE = 4
_INSTRUCTIONS = (
    "Gemini is unavailable. Claude Code performs the whole audit locally: (1) STRIDE threat-model the codebase from packed_text "
    "(and the real files); (2) trace attacker-controlled sources to dangerous sinks, verifying sanitizers/authz/reachability; "
    "(3) treat secret_findings, deep_findings and web_scan as leads to verify; (4) write MYTHOS_AUDIT.md and .mythos/report.json "
    "(MythosAuditReport: summary, findings[id,title,severity,confidence,cwe_id,owasp,cvss_score,cvss_vector,file,start_line,"
    "end_line,description,taint_flow[role,file,line,code,description],attack_vector,impact,remediation,proposed_patch_diff],"
    "threat_model[stride_category,component,threat,risk,mitigation,related_finding_ids]); (5) present the report to the user. "
    "Never print secret values."
)


def _fallback(out_dir: Path, target: str, packed=None, hits=(), deep_hits=(), web=None) -> None:
    """Hand the audit to Claude Code: write the local package and exit with code 4."""
    console.print("[yellow]!! Gemini unavailable or skipped (quota, missing key or --no-ai). Preparing local audit package for Claude Code...[/yellow]")
    (out_dir / ".mythos").mkdir(parents=True, exist_ok=True)
    pkg = {
        "target": target,
        "packed_text": packed.text if packed else None,
        "stack": packed.stack if packed else [],
        "secret_findings": [asdict(h) for h in hits],
        "deep_findings": [{**asdict(h), "severity": h.severity.value} for h in deep_hits],
        "web_scan": web.model_dump(mode="json") if web else None,
        "instructions": _INSTRUCTIONS,
    }
    (out_dir / PACKED_JSON).write_text(json.dumps(pkg, indent=2), encoding="utf-8")
    console.print(f"[green]Wrote {out_dir / PACKED_JSON}[/green]")
    raise typer.Exit(EXIT_CODE_FALLBACK_TO_CLAUDE)


def _version(value: bool) -> None:
    if value:
        console.print(f"mythos {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", callback=_version, is_eager=True, help="Show version."),
) -> None:
    pass


@app.command()
def setup() -> None:
    """Configure (or replace) your Gemini API key."""
    existing = get_gemini_api_key()
    if existing and not typer.confirm("A Gemini API key is already configured. Replace it?", default=False):
        console.print("[green]Keeping the existing key.[/green]")
        return
    from .config import KEY_URL, save_gemini_api_key

    console.print(f"Get a free key at [link]{KEY_URL}[/link]")
    key = typer.prompt("Paste your Gemini API key", hide_input=True).strip()
    if not key:
        console.print("[red]No key entered.[/red]")
        raise typer.Exit(1)
    console.print(f"[green]Saved to {save_gemini_api_key(key)}[/green]")


@app.command()
def audit(
    target: str = typer.Argument(".", help="Repository root to audit, or an http(s):// URL for a live web audit."),
    output: Path = typer.Option(None, "--output", "-o", help="Output directory (default: the repo root)."),
    model: str = typer.Option(DEFAULT_MODEL, "--model", "-m", help="Gemini model."),
    ignore: Optional[list[str]] = typer.Option(None, "--ignore", "-i", help="Extra gitignore-style patterns."),
    max_chars: int = typer.Option(3_600_000, help="Packed-context budget in characters (~4 chars/token)."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Pack and pre-scan only; do not call Gemini."),
    non_interactive: bool = typer.Option(False, "--non-interactive", help="Never prompt for an API key."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip Gemini; write the local package for Claude Code (exit 4)."),
    deep: bool = typer.Option(False, "--deep", "--own", help="Exhaustive audit of assets you own (Android, backend sinks; many more web probes)."),
) -> None:
    """Pack the repo, run Gemini threat modeling, and write MYTHOS_AUDIT.md + mythos.sarif.

    If TARGET starts with http:// or https:// this routes to the live web audit instead.
    """
    if target.lower().startswith(("http://", "https://")):
        return _web_audit(target, output, model, non_interactive, no_ai, deep)
    root = Path(target).resolve()
    out_dir = (output or root).resolve()
    try:
        with console.status("[bold cyan]Packing codebase…"):
            packed = pack_codebase(root, max_chars=max_chars, extra_ignores=ignore)
        with console.status("[bold cyan]Scanning for secrets…"):
            hits = scan_packed(packed.text)
        deep_hits = scan_deep(packed.text) if deep else []
    except (OSError, NotADirectoryError) as exc:
        console.print(f"[red]Cannot read {root}: {exc}[/red]")
        raise typer.Exit(2)

    st = packed.stats
    table = Table(title="Codebase", show_header=False)
    for k, v in [
        ("Root", str(root)), ("Stack", ", ".join(packed.stack) or "unknown"), ("Files", f"{st.files_packed:,}"),
        ("Lines", f"{st.total_lines:,}"), ("Est. tokens", f"{st.est_tokens:,}"),
        ("Skipped", f"{st.skipped_binary} binary, {st.skipped_large} large, {st.skipped_budget} over budget"),
        ("Secret candidates", str(len(hits))),
    ] + ([("Deep findings", str(len(deep_hits)))] if deep else []):
        table.add_row(k, v)
    console.print(table)
    if not packed.files:
        console.print("[red]No auditable files found.[/red]")
        raise typer.Exit(2)
    if st.skipped_budget:
        console.print("[yellow]Context budget exceeded: some files were omitted from the audit.[/yellow]")
    if dry_run:
        return

    if no_ai:
        _fallback(out_dir, str(root), packed, hits, deep_hits)
    try:
        key = ensure_gemini_api_key(interactive=not non_interactive)
    except MissingApiKeyError:
        _fallback(out_dir, str(root), packed, hits, deep_hits)

    hints = "\n".join(f"- {h.file}:{h.line} {h.kind} ({h.redacted})" for h in hits[:100])
    hints += "".join(f"\n- [deep] {h.file}:{h.line} {h.category} {h.title}" for h in deep_hits[:200])
    try:
        with console.status(f"[bold magenta]Gemini ({model}) is analyzing {st.files_packed} files… this can take minutes"):
            report: MythosAuditReport = run_audit(key, packed.text, packed.stack, hints, model)
    except GeminiQuotaError:
        _fallback(out_dir, str(root), packed, hits, deep_hits)
    except GeminiError as exc:
        console.print(f"[red]Audit failed: {exc}[/red]")
        raise typer.Exit(1)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / ".mythos").mkdir(exist_ok=True)
    write_markdown(report, out_dir / "MYTHOS_AUDIT.md", [f"`{h.file}:{h.line}` {h.kind} ({h.redacted})" for h in hits] + [f"`{h.file}:{h.line}` [deep] {h.title}" for h in deep_hits])
    write_sarif(report, out_dir / "mythos.sarif")
    (out_dir / REPORT_JSON).write_text(report.model_dump_json(indent=2), encoding="utf-8")

    findings = sorted(report.findings, key=lambda f: (list(SeverityEnum).index(f.severity), -f.cvss_score))
    result = Table(title=f"Findings (risk {report.summary.risk_score}/100)")
    for col in ("ID", "Severity", "CVSS", "CWE", "Title", "Location"):
        result.add_column(col)
    for f in findings:
        result.add_row(f.id, f"[{_STYLE[f.severity]}]{f.severity.value}[/]", f"{f.cvss_score:.1f}", f.cwe_id, f.title, f"{f.file}:{f.start_line}")
    console.print(result)
    console.print(f"[green]Wrote {out_dir / 'MYTHOS_AUDIT.md'}, mythos.sarif and {REPORT_JSON}[/green]")
    if any(f.severity in (SeverityEnum.CRITICAL, SeverityEnum.HIGH) for f in findings):
        raise typer.Exit(3)  # non-zero for CI gating on high-severity findings


def _web_audit(url: str, output: Optional[Path], model: str, non_interactive: bool, no_ai: bool, deep: bool = False) -> None:
    out_dir = (output or Path(".")).resolve()
    with console.status(f"[bold cyan]Auditing {url} (TLS, headers, CORS, cookies, exposure)…"):
        data = audit_web(url, deep=deep)
    if data.error:
        console.print(f"[red]Cannot reach {url}: {data.error}[/red]")
        raise typer.Exit(2)

    console.print(f"[bold]{data.final_url}[/bold]  HTTP {data.status}")
    t = data.tls
    if t.checked:
        console.print(f"TLS: {t.version or '?'} · {t.cipher or '?'} · issuer {t.issuer or '?'} · "
                      f"expires {t.not_after or '?'} ({t.days_left} days)" + (f" · [red]{t.verify_error}[/red]" if t.verify_error else ""))
    ok_style = {"ok": "green", "weak": "yellow", "missing": "red", "leak": "yellow"}
    tbl = Table(title="Security Headers")
    for col in ("Header", "Status", "Value / Note"):
        tbl.add_column(col, overflow="fold")
    for h in data.headers:
        tbl.add_row(h.name, f"[{ok_style.get(h.status, 'white')}]{h.status}[/]", (h.value[:80] + " " if h.value else "") + h.note)
    console.print(tbl)
    if data.cookies:
        ct = Table(title="Cookies")
        for col in ("Name", "Secure", "HttpOnly", "SameSite", "Problems"):
            ct.add_column(col)
        for c in data.cookies:
            ct.add_row(c.name, "yes" if c.secure else "[red]no[/]", "yes" if c.httponly else "[red]no[/]", c.samesite or "[red]-[/]", ", ".join(c.problems))
        console.print(ct)
    et = Table(title="CORS & Exposure")
    for col in ("Probe", "Result", "Note"):
        et.add_column(col, overflow="fold")
    for c in data.cors:
        et.add_row(f"CORS Origin: {c.origin}", "[red]REFLECTED[/]" if c.vulnerable else "ok", f"ACAO={c.allow_origin or '-'} ACAC={c.allow_credentials or '-'}")
    for e in data.exposures:
        et.add_row(e.path, f"[bold red]EXPOSED[/] ({e.status})" if e.confirmed else f"[green]{e.status or 'err'}[/]", e.note)
    console.print(et)

    report = None
    fallback = no_ai
    if not no_ai:
        try:
            key = ensure_gemini_api_key(interactive=not non_interactive)
            with console.status(f"[bold magenta]Gemini ({model}) is analyzing the web surface…"):
                report = run_web_audit(key, data, model)
        except (MissingApiKeyError, GeminiQuotaError):
            fallback = True
        except GeminiError as exc:
            console.print(f"[yellow]Skipping Gemini analysis: {exc}[/yellow]")
    if report:
        console.print(Panel(report.threat_narrative, title=f"Gemini Threat Narrative (risk {report.risk_score}/100)"))
        ft = Table(title="Gemini Findings")
        for col in ("ID", "Severity", "CWE", "Title"):
            ft.add_column(col)
        for f in sorted(report.findings, key=lambda f: list(SeverityEnum).index(f.severity)):
            ft.add_row(f.id, f"[{_STYLE[f.severity]}]{f.severity.value}[/]", f.cwe_id, f.title)
        console.print(ft)
    else:
        it = Table(title="Issues")
        for col in ("Severity", "Category", "Issue"):
            it.add_column(col)
        for i in data.issues:
            it.add_row(f"[{_STYLE[i.severity]}]{i.severity.value}[/]", i.category, i.title)
        console.print(it)

    (out_dir / ".mythos").mkdir(parents=True, exist_ok=True)
    write_web_markdown(data, report, out_dir / "MYTHOS_WEB_AUDIT.md")
    payload = {"scan": data.model_dump(mode="json"), "report": report.model_dump(mode="json") if report else None}
    (out_dir / ".mythos" / "web_report.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    console.print(f"[green]Wrote {out_dir / 'MYTHOS_WEB_AUDIT.md'} and .mythos/web_report.json[/green]")
    if fallback:
        _fallback(out_dir, url, web=data)
    if any(i.severity in (SeverityEnum.CRITICAL, SeverityEnum.HIGH) for i in data.issues):
        raise typer.Exit(3)


@app.command()
def web(
    url: str = typer.Argument(..., help="Live website URL, e.g. https://example.com"),
    output: Path = typer.Option(None, "--output", "-o", help="Output directory (default: current directory)."),
    model: str = typer.Option(DEFAULT_MODEL, "--model", "-m", help="Gemini model."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip Gemini; write the local package for Claude Code (exit 4)."),
    non_interactive: bool = typer.Option(False, "--non-interactive", help="Never prompt for an API key."),
    deep: bool = typer.Option(False, "--deep", "--own", help="Exhaustive probes (60+ paths, HTTP methods, CORS/CSP). Only for sites you own."),
) -> None:
    """Live web audit: TLS, headers, CSP, CORS, cookies, exposed files; Gemini DAST threat model."""
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    _web_audit(url, output, model, non_interactive, no_ai, deep)


@app.command()
def sca(path: Path = typer.Argument(Path("."), help="Project root with requirements.txt / pyproject.toml / package.json.")) -> None:
    """Dependency vulnerability scan (pip-audit + npm audit)."""
    with console.status("[bold cyan]Scanning dependencies…"):
        res = scan_dependencies(path.resolve())
    t = Table(title=f"Dependency vulnerabilities ({len(res.vulnerabilities)})")
    for col in ("Eco", "Package", "Version", "Advisory", "Severity", "Fix", "Link"):
        t.add_column(col, overflow="fold")
    for v in res.vulnerabilities:
        t.add_row(v.ecosystem, v.package, v.version, v.id, f"[{_STYLE[v.severity]}]{v.severity.value}[/]", ", ".join(v.fix_versions) or "-", v.link)
    console.print(t)
    for n in res.notes:
        console.print(f"[yellow]{n}[/yellow]")
    if res.vulnerabilities:
        raise typer.Exit(3)


if __name__ == "__main__":
    app()
