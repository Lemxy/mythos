---
description: Mythos security audit (Gemini threat modeling + local Claude verification and patching)
argument-hint: audit [path|url] [--deep] | web <url> [--deep] | sca [path] | fix <finding-id>
allowed-tools: Bash, Read, Edit, Grep, Glob
---

Arguments: `$ARGUMENTS`

You are driving the Mythos security suite. Parse the first word of the arguments.

## `audit [path]`
1. Run `mythos audit <path or .> --non-interactive`. If `mythos` is missing, tell the user to run `pip install -e <path to the mythos repo>`. A missing key or exhausted quota triggers the exit code 4 fallback below. Exit code 3 only means high/critical findings exist; it is not a failure. Exit code 4 means Gemini fallback: see below.
2. Read `MYTHOS_AUDIT.md` and `.mythos/report.json` from the audited directory.
3. Triage locally: for each CRITICAL/HIGH finding, open the cited file and lines and verify the taint flow is real (check sanitizers, auth, reachability). Mark each as CONFIRMED, FALSE POSITIVE (say why) or NEEDS REVIEW.
4. Present a short table: ID, severity, verdict, location. Suggest `/mythos fix <id>` for confirmed ones. Do not modify any files during audit.

## `web <url>` (also `audit <url>`)
1. Only for sites the user owns or is authorized to test. Run `mythos web <url> --non-interactive` (add `--no-ai` for scan-only). Exit code 3 only means high/critical issues exist. Exit code 4 means Gemini fallback: see below.
2. Read `MYTHOS_WEB_AUDIT.md` and `.mythos/web_report.json` (`scan` = raw evidence, `report` = Gemini analysis).
3. Verify each HIGH/CRITICAL: re-check the evidence yourself (e.g. `curl -sI <url>`, `curl -H "Origin: https://evil.com" -i <url>`); exposure probes are signature-checked but confirm before alarming. Verdict: CONFIRMED / FALSE POSITIVE / NEEDS REVIEW.
4. Covers: TLS (cert expiry, protocol, cipher), security headers + CSP analysis, CORS reflection with credentials, cookie flags, robots/security.txt, exposed `.git`, `.env`, compose, backups, OpenAPI/Swagger/GraphQL.
5. Gemini findings include exact fixes for Nginx, Apache, Caddy, Cloudflare and Express/Helmet.js. If the user's repo is local, offer to apply the matching config; do not change anything unasked.

## `sca [path]`
Run `mythos sca <path or .>`: pip-audit (requirements.txt / pyproject.toml) and npm audit (package.json + lockfile). Present vulnerable packages, advisory links and fixed versions; propose upgrades, do not apply unasked.

## `fix <finding-id>`
1. Load `.mythos/report.json` and find the finding with that `id`. If absent, tell the user to run `/mythos audit` first.
2. Re-verify the vulnerability in the current code. If it is already fixed or a false positive, stop and say so.
3. Apply the `proposed_patch_diff` if it applies cleanly; otherwise implement an equivalent minimal fix by hand in the project's style. Never touch unrelated code.
4. Run the project's tests/linter if present, and show the resulting `git diff`. Do not commit unless asked.

## Exit code 4: Gemini fallback (Claude takes over, never stop)

Exit code 4 (or a "Gemini quota exhausted / unavailable" notice, a missing key, or `--no-ai`) means Mythos wrote `.mythos/packed_for_claude.json` and handed the audit to you. You MUST NOT stop, apologize, or ask the user to fix quota or keys. Take over 100% of the audit locally:

1. Read `.mythos/packed_for_claude.json` (in the audited/output directory): `packed_text` (line-numbered files; large, so use Grep/offset reads or open the real files), `stack`, `secret_findings`, `deep_findings`, `web_scan` (for URL audits) and `instructions`.
2. Whole-codebase STRIDE threat model: components, trust boundaries, Spoofing/Tampering/Repudiation/Information disclosure/DoS/Elevation of privilege.
3. Trace attacker-controlled sources to dangerous sinks in the real code; check sanitizers, authz and reachability. Treat `secret_findings`, `deep_findings` and `web_scan` issues as leads to verify, not facts. For a web scan, re-check HIGH/CRITICAL evidence with `curl`.
4. Write `MYTHOS_AUDIT.md` (or `MYTHOS_WEB_AUDIT.md` for URLs) and `.mythos/report.json` (code audits: the MythosAuditReport schema listed in `instructions`, so `/mythos fix <id>` works).
5. Present the report to the user as if Gemini had produced it: table of ID, severity, verdict, `file:line`, then the threat model. Mention once, in a single line, that the local fallback was used.
6. Do not modify source files during the audit. Never print secret values.

## `--deep` / `--own` (exhaustive mode)

Only when the user states they own the target: add `--deep` (alias `--own`) to `mythos audit` / `mythos web`. Web: 70 signature-checked paths (secrets, admin/actuator, API docs, CI/CD, cloud), OPTIONS/TRACE/PUT/DELETE probes (PUT/DELETE touch only a random nonexistent path), CORS prefix/suffix/null/http bypasses, CSP frame-ancestors/form-action/base-uri. Code: Android manifest (exported components without permission, debuggable, allowBackup, cleartext), insecure WebView, hardcoded keystore passwords, DES/AES-ECB, plus backend sinks (SQLi, command injection, SSRF, deserialization, path traversal, IDOR). Verify these like any other lead.

With no or unknown arguments, print the usages above.
