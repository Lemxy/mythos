# Mythos

AI-assisted security audit and threat modeling. **Gemini** reads your whole repository in one
long-context pass (threat model, source-to-sink taint flows, CVSS, patch diffs); **Claude Code**
verifies findings locally, triages false positives and applies patches.

## Install

```bash
git clone https://github.com/Lemxy/mythos && cd mythos
pip install -e .
mythos setup        # paste a Gemini key from https://aistudio.google.com/apikey
```

Key lookup order: `GEMINI_API_KEY` env var → `./.env` → `~/.mythos/.env`. `setup` (or the first
interactive `audit`) saves it to `~/.mythos/.env`. Python 3.10+.

## Usage

```bash
mythos audit [PATH] [--model gemini-3.1-pro-preview] [-i PATTERN] [-o OUTDIR] [--dry-run] [--non-interactive] [--no-ai] [--deep|--own]
```

Outputs, written to the repo root (or `-o`):

| File | Purpose |
|---|---|
| `MYTHOS_AUDIT.md` | Human report: summary, findings, taint flows, patches, STRIDE model |
| `mythos.sarif` | SARIF 2.1.0 for GitHub code scanning / IDEs |
| `.mythos/report.json` | Full structured report, used by `/mythos fix` |

`--dry-run` packs and runs the secret scan without calling Gemini (useful to check token size).
Exit code is `3` when CRITICAL/HIGH findings exist, so it can gate CI. Set `MYTHOS_MODEL` to change the default model.

### Live web audit and dependency scan

```bash
mythos web https://example.com [-o OUTDIR] [-m MODEL] [--no-ai] [--deep|--own]   # or: mythos audit https://example.com
mythos sca [PATH]
```

`audit` routes any `http://` / `https://` target to the web audit. The scanner (read-only GET probes) checks:
TLS (cert validity/expiry, protocol, cipher, legacy TLS 1.0/1.1), security headers (CSP with unsafe-inline/eval/wildcard
analysis, HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, Server/X-Powered-By leaks), CORS
reflection (`https://evil.com`, `null`, with credentials), cookie flags, `robots.txt`, `security.txt`, and exposed
`.git/HEAD`, `.env`, `docker-compose.yml`, `backup.zip`, OpenAPI/Swagger/GraphQL (content-signature checked to avoid SPA false positives).
Gemini then writes a DAST threat narrative with attack scenarios (clickjacking, CSRF, DOM XSS, CORS credential theft, session
hijacking) and exact fixes for Nginx, Apache, Caddy, Cloudflare and Express/Helmet.js. Outputs: `MYTHOS_WEB_AUDIT.md`, `.mythos/web_report.json`.
Exit code `3` on HIGH/CRITICAL issues.

`mythos sca` runs `pip-audit` (requirements.txt / pyproject.toml) and `npm audit` (package.json + lockfile; needs npm) and lists
advisories with links and fixed versions. Only scan sites you own or are authorized to test.

### Zero-downtime Gemini fallback

If Gemini returns 429 / `RESOURCE_EXHAUSTED` / quota errors (`GeminiQuotaError`), the API key is missing, or `--no-ai` is passed,
Mythos prints a notice, writes `.mythos/packed_for_claude.json` (packed text, stack, secret findings, deep findings, web scan,
instructions) and exits with code `4`. `/mythos` in Claude Code then performs the whole audit itself (STRIDE, source-to-sink
tracing) and writes `MYTHOS_AUDIT.md` + `.mythos/report.json`. For web scans the normal scan outputs are still written first.

### Deep mode (`--deep` / `--own`): only for assets you own

- Web: 70 signature-checked paths (`.env*`, `.git/*`, SQL dumps, Spring Actuator, phpMyAdmin/pgAdmin, Swagger/GraphQL, CI/CD, `.aws/credentials`...),
  OPTIONS/TRACE/PUT/DELETE probes (PUT/DELETE only touch a random nonexistent path, cleaned up afterwards), CORS prefix/suffix/null/http
  reflection, CSP `frame-ancestors` / `form-action` / `base-uri`.
- Code (`scanner/deep.py`): Android manifest (exported components without permission, `debuggable`, `allowBackup`, cleartext traffic),
  insecure WebView, hardcoded keystore passwords, DES/AES-ECB, and backend sinks (SQLi, command injection, SSRF, deserialization,
  path traversal, IDOR). Heuristic leads passed to Gemini (or Claude in fallback), not proof.

### Inside Claude Code

Copy `claude/mythos.md` to `~/.claude/commands/mythos.md` to get the slash command:

- `/mythos audit [path]` runs the audit, then verifies each high/critical finding against the code.
- `/mythos web <url>` and `/mythos sca [path]` run the live web audit and dependency scan, then verify the results.
- `/mythos fix MYTHOS-001` re-verifies one finding, applies its patch, and runs your tests.

## Architecture

```
scanner/packer.py   walk repo (.gitignore + built-in ignores, binary skip), detect stack,
                    emit line-numbered text, stats, token estimate
scanner/secrets.py  regex + Shannon entropy pre-scan (hints for the model, redacted)
ai/schema.py        Pydantic models = Gemini response schema (MythosAuditReport)
ai/prompts.py       AppSec/threat-modeler system prompt (no false positives, taint flows, diffs)
ai/gemini_client.py google-genai call with structured JSON; retries without response_schema
reporter/           sarif.py, markdown.py
scanner/deep.py     --deep static rules: Android manifest/WebView/crypto, backend sinks
scanner/web.py      live web audit (TLS, headers, CORS, cookies, exposure) -> WebAuditData
scanner/sca.py      pip-audit / npm audit wrapper
cli.py              Typer commands: setup, audit, web, sca
```

## Limits

- Only the root `.gitignore` is honored; nested ones are ignored.
- The pack budget is ~3.6M characters (~900k tokens); extra files are skipped and reported.
- LLM findings are leads, not proof. Review before patching; the Claude Code step exists for that.
- Source code is sent to Google's Gemini API. Do not audit code you are not allowed to share.
