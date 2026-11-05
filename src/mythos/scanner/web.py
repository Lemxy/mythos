"""Live web application audit: TLS, security headers, CORS, cookies, recon and exposure probes.

All probes are read-only GET requests with bounded response size; nothing is exploited.
"""

from __future__ import annotations

import re
import secrets
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field

from ..ai.schema import SeverityEnum

S = SeverityEnum
UA = "Mythos-WebAudit/0.2 (+defensive security scan)"


class WebIssue(BaseModel):
    category: str = Field(description="tls, header, csp, cors, cookie, method, exposure or recon")
    severity: SeverityEnum
    title: str
    detail: str = ""


class TlsInfo(BaseModel):
    checked: bool = False
    version: str = ""
    cipher: str = ""
    cipher_bits: int = 0
    subject: str = ""
    issuer: str = ""
    not_after: str = ""
    days_left: int | None = None
    verify_error: str = ""
    legacy_versions_accepted: list[str] = Field(default_factory=list)


class HeaderResult(BaseModel):
    name: str
    value: str = ""
    present: bool = False
    status: str = Field(default="", description="ok, weak, missing or leak")
    note: str = ""


class CorsResult(BaseModel):
    origin: str
    allow_origin: str = ""
    allow_credentials: str = ""
    vulnerable: bool = False


class CookieResult(BaseModel):
    name: str
    secure: bool
    httponly: bool
    samesite: str = ""
    problems: list[str] = Field(default_factory=list)


class ExposureResult(BaseModel):
    path: str
    status: int
    confirmed: bool = False
    note: str = ""


class WebAuditData(BaseModel):
    url: str
    final_url: str = ""
    status: int = 0
    error: str = ""
    tls: TlsInfo = Field(default_factory=TlsInfo)
    headers: list[HeaderResult] = Field(default_factory=list)
    cors: list[CorsResult] = Field(default_factory=list)
    cookies: list[CookieResult] = Field(default_factory=list)
    exposures: list[ExposureResult] = Field(default_factory=list)
    robots_txt: str = ""
    security_txt: bool = False
    issues: list[WebIssue] = Field(default_factory=list)


# path -> (content signature check, severity, note). The signature avoids SPA "200 for everything" false positives.
_PROBES = {
    "/.git/HEAD": (lambda t: t.startswith("ref:"), S.CRITICAL, "Git repository exposed: source and history downloadable"),
    "/.env": (lambda t: "=" in t and "<html" not in t.lower()[:300], S.CRITICAL, "Environment file with likely secrets exposed"),
    "/docker-compose.yml": (lambda t: "services:" in t, S.HIGH, "Docker compose file exposed"),
    "/backup.zip": (lambda t: t.startswith("PK"), S.HIGH, "Backup archive downloadable"),
    "/openapi.json": (lambda t: '"openapi"' in t or '"swagger"' in t, S.LOW, "OpenAPI spec publicly exposed"),
    "/swagger.json": (lambda t: '"swagger"' in t or '"openapi"' in t, S.LOW, "Swagger spec publicly exposed"),
    "/api/docs": (lambda t: any(k in t.lower() for k in ("swagger", "redoc", "openapi")), S.LOW, "API docs UI exposed"),
    "/graphql": (lambda t: "graphql" in t.lower() or '"errors"' in t, S.LOW, "GraphQL endpoint reachable (check introspection/auth)"),
}


def _env(t):
    return bool(re.search(r"^[A-Za-z0-9_.]+\s*=", t, re.M)) and "<html" not in t.lower()[:300]


def _has(*keys):
    return lambda t: any(k in t for k in keys)


def _hasl(*keys):
    return lambda t: any(k in t.lower() for k in keys)


def _admin(t):
    low = t.lower()
    return "<html" in low and any(k in low for k in ("login", "password", "sign in", "admin"))


_SQL = _has("INSERT INTO", "CREATE TABLE", "MySQL dump", "PostgreSQL database dump")
# deep-mode extras (merged over _PROBES): every check is content-signature based, so SPA catch-alls do not trip them.
_DEEP_PROBES = {
    # config & secrets
    "/.env.local": (_env, S.CRITICAL, "Local environment file exposed"),
    "/.env.production": (_env, S.CRITICAL, "Production environment file exposed"),
    "/.env.development": (_env, S.HIGH, "Development environment file exposed"),
    "/.env.backup": (_env, S.CRITICAL, "Environment backup exposed"),
    "/.git/config": (_has("[core]"), S.CRITICAL, "Git config exposed (repository downloadable)"),
    "/.git/index": (_has("DIRC"), S.HIGH, "Git index exposed (file listing)"),
    "/.git/logs/HEAD": (lambda t: bool(re.match(r"[0-9a-f]{40} ", t)), S.HIGH, "Git reflog exposed"),
    "/.svn/entries": (_has("svn:"), S.HIGH, "SVN metadata exposed"),
    "/.hg/hgrc": (_has("[paths]"), S.HIGH, "Mercurial config exposed"),
    "/.DS_Store": (_has("Bud1"), S.LOW, "macOS .DS_Store exposed (file listing)"),
    "/.htpasswd": (lambda t: bool(re.match(r"[\w.-]+:(\$apr1\$|\$2y\$|\{SHA\}|[./0-9A-Za-z]{13})", t)), S.CRITICAL, "htpasswd credentials exposed"),
    "/.npmrc": (_has("_authToken", "registry="), S.HIGH, "npm config (possible token) exposed"),
    "/.ssh/id_rsa": (_has("PRIVATE KEY"), S.CRITICAL, "SSH private key exposed"),
    "/id_rsa": (_has("PRIVATE KEY"), S.CRITICAL, "SSH private key exposed"),
    "/Dockerfile": (lambda t: bool(re.search(r"^FROM ", t, re.M)), S.MEDIUM, "Dockerfile exposed"),
    "/server.js.bak": (_has("require(", "express", "app.listen"), S.HIGH, "Server source backup exposed"),
    "/web.config": (_has("<configuration"), S.HIGH, "IIS web.config exposed"),
    "/appsettings.json": (_has("ConnectionStrings", "AllowedHosts", '"Logging"'), S.HIGH, "ASP.NET appsettings.json exposed"),
    "/config/database.yml": (_has("adapter:", "database:"), S.CRITICAL, "Rails database.yml exposed"),
    "/wp-config.php.bak": (_has("DB_PASSWORD"), S.CRITICAL, "WordPress config backup exposed"),
    "/terraform.tfstate": (_has("terraform_version"), S.CRITICAL, "Terraform state exposed (secrets)"),
    "/backup.sql": (_SQL, S.CRITICAL, "SQL dump downloadable"),
    "/dump.sql": (_SQL, S.CRITICAL, "SQL dump downloadable"),
    "/db.sql": (_SQL, S.CRITICAL, "SQL dump downloadable"),
    "/database.sql": (_SQL, S.CRITICAL, "SQL dump downloadable"),
    "/site.zip": (lambda t: t.startswith("PK"), S.HIGH, "Site archive downloadable"),
    "/www.zip": (lambda t: t.startswith("PK"), S.HIGH, "Site archive downloadable"),
    "/backup.tar.gz": (lambda t: t.startswith("\x1f"), S.HIGH, "Backup archive downloadable"),
    "/phpinfo.php": (_has("phpinfo()", "PHP Version"), S.MEDIUM, "phpinfo() page exposed"),
    "/server-status": (_has("Apache Server Status"), S.MEDIUM, "Apache server-status exposed"),
    "/package.json": (_has('"dependencies"', '"scripts"'), S.LOW, "package.json exposed (dependency disclosure)"),
    # admin & internal portals
    "/admin": (_admin, S.LOW, "Admin login reachable"),
    "/administrator": (_admin, S.LOW, "Administrator login reachable"),
    "/console": (_hasl("werkzeug", "h2 console", "debugger"), S.CRITICAL, "Interactive debug/DB console exposed"),
    "/phpmyadmin": (_hasl("phpmyadmin"), S.MEDIUM, "phpMyAdmin exposed"),
    "/pgadmin": (_hasl("pgadmin"), S.MEDIUM, "pgAdmin exposed"),
    "/actuator": (_has('"_links"'), S.MEDIUM, "Spring Actuator index exposed"),
    "/actuator/env": (_has("propertySources"), S.CRITICAL, "Spring Actuator /env exposed (config and secrets)"),
    "/actuator/heapdump": (_has("JAVA PROFILE"), S.CRITICAL, "Spring Actuator heap dump downloadable"),
    "/actuator/health": (lambda t: '"status"' in t and ("UP" in t or "DOWN" in t), S.LOW, "Spring Actuator /health exposed"),
    "/actuator/mappings": (_has("dispatcherServlet", "contexts"), S.HIGH, "Spring Actuator /mappings exposed (route map)"),
    "/actuator/configprops": (_has("contexts", "beans"), S.HIGH, "Spring Actuator /configprops exposed"),
    "/actuator/beans": (_has('"beans"'), S.MEDIUM, "Spring Actuator /beans exposed"),
    "/actuator/threaddump": (_has('"threads"'), S.MEDIUM, "Spring Actuator /threaddump exposed"),
    "/actuator/loggers": (_has('"levels"'), S.MEDIUM, "Spring Actuator /loggers exposed"),
    "/metrics": (_has("# HELP"), S.LOW, "Prometheus metrics exposed"),
    "/elmah.axd": (_has("Error Log for"), S.HIGH, "ELMAH error log exposed"),
    "/_profiler": (_hasl("symfony"), S.HIGH, "Symfony profiler exposed"),
    "/telescope": (_hasl("telescope"), S.HIGH, "Laravel Telescope exposed"),
    # API & documentation
    "/swagger/v1/swagger.json": (_has('"swagger"', '"openapi"'), S.LOW, "Swagger spec publicly exposed"),
    "/v2/api-docs": (_has('"swagger"'), S.LOW, "Springfox API docs exposed"),
    "/v3/api-docs": (_has('"openapi"'), S.LOW, "OpenAPI v3 docs exposed"),
    "/graphiql": (_hasl("graphiql"), S.MEDIUM, "GraphiQL IDE exposed"),
    "/api/graphql": (_hasl("graphql", '"errors"'), S.LOW, "GraphQL endpoint reachable (check introspection/auth)"),
    # CI/CD & cloud
    "/.gitlab-ci.yml": (_has("stages:", "script:"), S.HIGH, "GitLab CI config exposed"),
    "/.github/workflows": (_has("jobs:", "Index of"), S.MEDIUM, "GitHub workflows exposed"),
    "/.travis.yml": (_has("language:"), S.MEDIUM, "Travis CI config exposed"),
    "/.circleci/config.yml": (_has("jobs:", "version:"), S.MEDIUM, "CircleCI config exposed"),
    "/Jenkinsfile": (_has("pipeline", "stage("), S.MEDIUM, "Jenkinsfile exposed"),
    "/bitbucket-pipelines.yml": (_has("pipelines:"), S.MEDIUM, "Bitbucket pipelines exposed"),
    "/.aws/credentials": (_hasl("aws_access_key_id"), S.CRITICAL, "AWS credentials file exposed"),
    "/.aws/config": (_has("[default]", "[profile"), S.HIGH, "AWS config exposed"),
}


def _handshake(host: str, port: int, ctx: ssl.SSLContext):
    with socket.create_connection((host, port), timeout=8) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
        return s.getpeercert(), s.version() or "", s.cipher() or ("", "", 0)


def _tls_audit(host: str, port: int) -> tuple[TlsInfo, list[WebIssue]]:
    info, issues = TlsInfo(checked=True), []
    cert = {}
    try:
        cert, info.version, (info.cipher, _, info.cipher_bits) = _handshake(host, port, ssl.create_default_context())
    except ssl.SSLCertVerificationError as exc:
        info.verify_error = exc.verify_message or str(exc)
        issues.append(WebIssue(category="tls", severity=S.HIGH, title="Certificate fails validation", detail=info.verify_error))
        uctx = ssl.create_default_context()
        uctx.check_hostname, uctx.verify_mode = False, ssl.CERT_NONE
        try:  # still report protocol/cipher
            _, info.version, (info.cipher, _, info.cipher_bits) = _handshake(host, port, uctx)
        except OSError:
            pass
    except OSError as exc:  # includes ssl.SSLError
        issues.append(WebIssue(category="tls", severity=S.HIGH, title="TLS handshake failed", detail=str(exc)))
        return info, issues

    if cert:
        flat = lambda k: ", ".join(v for rdn in cert.get(k, ()) for _, v in rdn)  # noqa: E731
        info.subject, info.issuer, info.not_after = flat("subject"), flat("issuer"), cert.get("notAfter", "")
        if info.not_after:
            exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(info.not_after), timezone.utc)
            info.days_left = (exp - datetime.now(timezone.utc)).days
            if info.days_left < 0:
                issues.append(WebIssue(category="tls", severity=S.CRITICAL, title="Certificate expired", detail=f"Expired {-info.days_left} days ago"))
            elif info.days_left < 30:
                issues.append(WebIssue(category="tls", severity=S.MEDIUM, title="Certificate expires soon", detail=f"{info.days_left} days left"))
    if info.version and info.version not in ("TLSv1.2", "TLSv1.3"):
        issues.append(WebIssue(category="tls", severity=S.HIGH, title=f"Negotiated weak protocol {info.version}"))
    if (info.cipher_bits and info.cipher_bits < 128) or any(w in info.cipher for w in ("RC4", "3DES", "NULL", "EXPORT", "MD5")):
        issues.append(WebIssue(category="tls", severity=S.HIGH, title="Weak cipher suite", detail=f"{info.cipher} ({info.cipher_bits} bits)"))

    # shortcut: if the local OpenSSL refuses legacy protocols the probe reports "not accepted"; use a legacy-enabled build for certainty.
    for label, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
            c.minimum_version = c.maximum_version = ver
            c.set_ciphers("ALL:@SECLEVEL=0")
            _handshake(host, port, c)
            info.legacy_versions_accepted.append(label)
            issues.append(WebIssue(category="tls", severity=S.MEDIUM, title=f"Server accepts deprecated {label}"))
        except (OSError, ValueError):
            pass
    return info, issues


def _csp_issues(csp: str, deep: bool = False) -> list[WebIssue]:
    out = []
    directives = {d.split()[0].lower(): d.split()[1:] for d in csp.split(";") if d.strip()}
    scripts = directives.get("script-src", directives.get("default-src", []))
    if "'unsafe-inline'" in scripts and not any(t.startswith(("'nonce-", "'sha")) for t in scripts):
        out.append(WebIssue(category="csp", severity=S.MEDIUM, title="CSP allows 'unsafe-inline' scripts", detail="Defeats XSS mitigation"))
    if "'unsafe-eval'" in scripts:
        out.append(WebIssue(category="csp", severity=S.MEDIUM, title="CSP allows 'unsafe-eval'"))
    for d, vals in directives.items():
        if d in ("script-src", "default-src", "object-src") and any(v in ("*", "http:", "https:", "data:") for v in vals):
            out.append(WebIssue(category="csp", severity=S.MEDIUM, title=f"CSP {d} uses a wildcard/scheme source", detail=" ".join(vals)))
    if "default-src" not in directives and "script-src" not in directives:
        out.append(WebIssue(category="csp", severity=S.MEDIUM, title="CSP has no default-src/script-src"))
    if "frame-ancestors" not in directives:
        out.append(WebIssue(category="csp", severity=S.LOW, title="CSP lacks frame-ancestors", detail="Clickjacking relies on X-Frame-Options"))
    if deep:
        for d, why in (("form-action", "forms can post to any origin (credential phishing via injected forms)"), ("base-uri", "an injected <base> can hijack relative script URLs")):
            if d not in directives:
                out.append(WebIssue(category="csp", severity=S.LOW, title=f"CSP lacks {d}", detail=why))
    return out


def _header_audit(h: httpx.Headers, https: bool, deep: bool = False) -> tuple[list[HeaderResult], list[WebIssue]]:
    res, issues = [], []

    def add(name, status, note, sev=None, title=None):
        v = h.get(name, "")
        res.append(HeaderResult(name=name, value=v[:300], present=bool(v), status=status, note=note))
        if sev:
            issues.append(WebIssue(category="header", severity=sev, title=title or f"{name}: {note}", detail=v[:200]))

    csp = h.get("content-security-policy")
    if csp:
        ci = _csp_issues(csp, deep)
        issues += ci
        add("Content-Security-Policy", "weak" if ci else "ok", "; ".join(i.title for i in ci))
    else:
        add("Content-Security-Policy", "missing", "not set", S.MEDIUM, "Missing Content-Security-Policy")

    hsts = h.get("strict-transport-security", "").lower().replace(" ", "")
    if not https:
        add("Strict-Transport-Security", "missing", "site served over plain HTTP", S.HIGH, "Site served over HTTP (no TLS)")
    elif not hsts:
        add("Strict-Transport-Security", "missing", "not set", S.MEDIUM, "Missing HSTS")
    else:
        age = next((int(p[8:]) for p in hsts.split(";") if p.startswith("max-age=") and p[8:].isdigit()), 0)
        sub = "includesubdomains" in hsts
        weak = age < 15552000 or not sub
        add("Strict-Transport-Security", "weak" if weak else "ok", f"max-age={age}" + ("" if sub else ", no includeSubDomains"),
            S.LOW if weak else None, "Weak HSTS policy")

    xfo = h.get("x-frame-options", "").lower()
    if xfo in ("deny", "sameorigin") or "frame-ancestors" in (csp or ""):
        add("X-Frame-Options", "ok", xfo or "covered by CSP frame-ancestors")
    else:
        add("X-Frame-Options", "missing", "clickjacking possible", S.MEDIUM, "Missing clickjacking protection")

    if h.get("x-content-type-options", "").lower() == "nosniff":
        add("X-Content-Type-Options", "ok", "nosniff")
    else:
        add("X-Content-Type-Options", "missing", "MIME sniffing allowed", S.LOW, "Missing X-Content-Type-Options: nosniff")

    rp = h.get("referrer-policy", "").lower()
    if not rp:
        add("Referrer-Policy", "missing", "not set", S.LOW, "Missing Referrer-Policy")
    elif rp in ("unsafe-url", "no-referrer-when-downgrade"):
        add("Referrer-Policy", "weak", rp, S.LOW, "Leaky Referrer-Policy")
    else:
        add("Referrer-Policy", "ok", rp)

    if h.get("permissions-policy") or h.get("feature-policy"):
        add("Permissions-Policy", "ok", "set")
    else:
        add("Permissions-Policy", "missing", "not set", S.LOW, "Missing Permissions-Policy")

    for name in ("server", "x-powered-by", "x-aspnet-version"):
        v = h.get(name, "")
        if v and (name != "server" or any(c.isdigit() for c in v)):
            add(name, "leak", "technology/version disclosed", S.LOW, f"Information disclosure via {name}: {v[:60]}")
        else:
            res.append(HeaderResult(name=name, value=v, present=bool(v), status="ok", note="no version disclosed" if v else "not disclosed"))
    return res, issues


def _cookie_audit(resp: httpx.Response) -> tuple[list[CookieResult], list[WebIssue]]:
    out, issues = [], []
    for raw in resp.headers.get_list("set-cookie"):
        parts = [p.strip() for p in raw.split(";")]
        attrs = {p.split("=")[0].lower(): p.partition("=")[2] for p in parts[1:]}
        name = parts[0].split("=")[0]
        c = CookieResult(name=name, secure="secure" in attrs, httponly="httponly" in attrs, samesite=attrs.get("samesite", ""))
        if not c.secure:
            c.problems.append("missing Secure")
        if not c.httponly:
            c.problems.append("missing HttpOnly")
        if not c.samesite:
            c.problems.append("missing SameSite")
        elif c.samesite.lower() == "none" and not c.secure:
            c.problems.append("SameSite=None without Secure")
        if c.problems:
            sensitive = any(k in name.lower() for k in ("sess", "auth", "token", "sid", "jwt"))
            issues.append(WebIssue(category="cookie", severity=S.MEDIUM if sensitive else S.LOW, title=f"Cookie '{name}': {', '.join(c.problems)}"))
        out.append(c)
    return out, issues


def _cors_audit(client: httpx.Client, url: str, deep: bool = False) -> tuple[list[CorsResult], list[WebIssue]]:
    out, issues = [], []
    origins = ["https://evil.com", "null"]
    if deep:  # suffix bypass (target.com.evil.com), prefix bypass (eviltarget.com), http downgrade reflection
        p = urlparse(url)
        host = p.hostname or ""
        origins += [f"https://{host}.evil.com", f"https://evil{host}"] + ([f"http://{host}"] if p.scheme == "https" else [])
    for origin in origins:
        try:
            r = client.get(url, headers={"Origin": origin})
        except httpx.HTTPError:
            continue
        ao = r.headers.get("access-control-allow-origin", "")
        creds = r.headers.get("access-control-allow-credentials", "").lower() == "true"
        reflected = ao == origin
        out.append(CorsResult(origin=origin, allow_origin=ao, allow_credentials=str(creds).lower() if creds else "", vulnerable=reflected))
        if reflected and creds:
            issues.append(WebIssue(category="cors", severity=S.HIGH, title=f"CORS reflects Origin '{origin}' with credentials", detail="Cross-site pages can read authenticated responses"))
        elif reflected:
            issues.append(WebIssue(category="cors", severity=S.MEDIUM, title=f"CORS reflects arbitrary Origin '{origin}'"))
        elif ao == "*" and origin != "null":
            issues.append(WebIssue(category="cors", severity=S.LOW, title="CORS allows any origin (*)", detail="Browsers refuse credentials with *, so only public data is exposed"))
    return out, issues


def _probe(client: httpx.Client, base: str, path: str, check, sev, note) -> tuple[ExposureResult, WebIssue | None]:
    try:
        with client.stream("GET", base + path, headers={"Range": "bytes=0-2047"}) as r:
            body = b""
            for chunk in r.iter_bytes():
                body += chunk
                if len(body) >= 2048:
                    break
            text = body[:2048].decode("utf-8", "ignore")
            ok = r.status_code in (200, 206) and bool(text) and check(text)
            res = ExposureResult(path=path, status=r.status_code, confirmed=ok, note=note if ok else "")
    except httpx.HTTPError as exc:
        return ExposureResult(path=path, status=0, note=type(exc).__name__), None
    return res, (WebIssue(category="exposure", severity=sev, title=f"{path} exposed", detail=note) if ok else None)


def _method_audit(client: httpx.Client, base: str) -> list[WebIssue]:
    """OPTIONS/TRACE/PUT/DELETE. Writes only to a random nonexistent path and removes it if the PUT worked."""
    issues, tag = [], secrets.token_hex(6)
    probe = f"{base}/mythos-probe-{tag}.txt"
    try:
        allow = client.options(base + "/").headers.get("allow", "").upper()
        risky = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT") if m in allow]
        if risky:
            issues.append(WebIssue(category="method", severity=S.LOW, title=f"OPTIONS advertises {', '.join(risky)}", detail=f"Allow: {allow}"))
        t = client.request("TRACE", base + "/", headers={"X-Mythos-Trace": tag})
        if t.status_code == 200 and tag in t.text:
            issues.append(WebIssue(category="method", severity=S.MEDIUM, title="TRACE enabled (request echoed)", detail="Cross-site tracing can expose headers"))
        catchall = client.get(f"{base}/mythos-absent-{tag}").status_code == 200  # SPAs answer 200 to everything
        put = client.put(probe, content=b"mythos")
        if put.status_code in (200, 201, 204) and client.get(probe).text.strip() == "mythos":
            issues.append(WebIssue(category="method", severity=S.HIGH, title="PUT creates files without authentication", detail=f"{put.status_code} on /mythos-probe-*.txt"))
            client.delete(probe)
        elif not catchall and client.delete(f"{base}/mythos-absent-{tag}").status_code in (200, 202, 204):
            issues.append(WebIssue(category="method", severity=S.MEDIUM, title="DELETE succeeds on an unauthenticated nonexistent resource", detail="Verify DELETE requires auth"))
    except httpx.HTTPError:
        pass
    return issues


def audit_web(url: str, timeout: float = 10.0, deep: bool = False) -> WebAuditData:
    """Scan a live site. ``deep`` adds 60+ signature-checked paths, HTTP method, CORS-bypass and CSP checks (own assets only)."""
    p = urlparse(url)
    data = WebAuditData(url=url)
    if p.scheme == "https":
        data.tls, ti = _tls_audit(p.hostname or "", p.port or 443)
        data.issues += ti
    # an invalid cert must not stop the HTTP-level audit
    with httpx.Client(timeout=timeout, follow_redirects=True, verify=not data.tls.verify_error, headers={"User-Agent": UA}) as client:
        try:
            resp = client.get(url)
        except httpx.HTTPError as exc:
            data.error = f"{type(exc).__name__}: {exc}"
            return data
        data.final_url, data.status = str(resp.url), resp.status_code
        https = resp.url.scheme == "https"
        fp = urlparse(data.final_url)
        base = f"{fp.scheme}://{fp.netloc}"
        if not https and p.scheme == "https":
            data.issues.append(WebIssue(category="tls", severity=S.HIGH, title="HTTPS request redirected to plain HTTP"))
        data.headers, hi = _header_audit(resp.headers, https, deep)
        data.cookies, ci = _cookie_audit(resp)
        data.cors, co = _cors_audit(client, data.final_url, deep)
        data.issues += hi + ci + co

        try:
            rb = client.get(base + "/robots.txt")
            if rb.status_code == 200 and "html" not in rb.headers.get("content-type", ""):
                data.robots_txt = rb.text[:2000]
                hidden = [l for l in rb.text.splitlines() if l.lower().startswith("disallow:") and any(k in l.lower() for k in ("admin", "backup", "private", "internal", "secret", "config"))]
                if hidden:
                    data.issues.append(WebIssue(category="recon", severity=S.INFO, title="robots.txt advertises sensitive paths", detail="; ".join(hidden[:5])))
            for sp in ("/.well-known/security.txt", "/security.txt"):
                s = client.get(base + sp)
                if s.status_code == 200 and "contact:" in s.text.lower():
                    data.security_txt = True
                    break
            if not data.security_txt:
                data.issues.append(WebIssue(category="recon", severity=S.INFO, title="No security.txt (RFC 9116) published"))
        except httpx.HTTPError:
            pass

        if deep:
            data.issues += _method_audit(client, base)
        for path, (check, sev, note) in ({**_PROBES, **_DEEP_PROBES} if deep else _PROBES).items():
            res, iss = _probe(client, base, path, check, sev, note)
            data.exposures.append(res)
            if iss:
                data.issues.append(iss)
    data.issues.sort(key=lambda i: list(SeverityEnum).index(i.severity))
    return data


scan_web_target = audit_web
