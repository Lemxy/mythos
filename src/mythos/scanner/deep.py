"""Deep static analyzer (--deep / --own): Android app hardening and web-backend sink heuristics.

Runs on packer output. Findings are leads for the model / Claude to verify, not proof.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from ..ai.schema import SeverityEnum as S

_A = "{http://schemas.android.com/apk/res/android}"
_COMPONENTS = ("activity", "activity-alias", "service", "receiver", "provider")
_CODE = (".java", ".kt", ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".go", ".cs")
_REQ = r"(?:req|request|params|query|body|args|input|user|ctx)\b"


@dataclass(frozen=True)
class DeepHit:
    file: str
    line: int
    category: str
    severity: S
    title: str


# (category, severity, title, regex, file suffixes or None for all code files)
_RULES: list[tuple[str, S, str, re.Pattern[str], tuple[str, ...] | None]] = [(c, s, t, re.compile(r, re.I if i else 0), x) for c, s, t, r, x, i in [
    ("android-crypto", S.MEDIUM, "Weak crypto: DES / AES-ECB (bare 'AES' defaults to ECB)", r"""Cipher\.getInstance\(\s*["'](?:DES[^"']*|[^"']*ECB[^"']*|AES)["']""", None, False),
    ("android-keystore", S.HIGH, "Hardcoded keystore/signing password", r"""(?:store|key)Password\s*[=:(]?\s*["'][^"'$]{3,}["']""", (".gradle", ".kts", ".properties", ".java", ".kt"), True),
    ("android-webview", S.MEDIUM, "WebView allows file access", r"""setAllowFileAccess(?:FromFileURLs)?\(\s*true|setAllowUniversalAccessFromFileURLs\(\s*true""", None, False),
    ("sqli", S.HIGH, "SQL built by string concatenation/formatting", r"""(?:execute|query|rawQuery|raw|prepare)\w*\(\s*(?:f["']|["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*(?:\+|%|\.format)|`[^`]*\$\{)""", _CODE, True),
    ("cmd-injection", S.HIGH, "OS command execution / eval sink", r"""os\.system\(|subprocess\.\w+\([^)]*shell\s*=\s*True|child_process|\bexecSync?\(|Runtime\.getRuntime\(\)\.exec|\beval\(|\bshell_exec\(|\bpassthru\(""", _CODE, False),
    ("ssrf", S.MEDIUM, "Outbound request to request-derived URL", rf"""(?:requests\.\w+|httpx\.\w+|urlopen|fetch|axios(?:\.\w+)?|http\.get|file_get_contents|curl_init)\(\s*[^"')\s][^)]*?\b{_REQ}""", _CODE, False),
    ("deserialization", S.HIGH, "Unsafe deserialization", r"""pickle\.loads?\(|yaml\.load\((?![^)]*Loader)|marshal\.loads|ObjectInputStream|\bunserialize\(|node-serialize|Marshal\.load""", _CODE, False),
    ("path-traversal", S.MEDIUM, "File access with request-derived path", rf"""(?:\bopen|readFile\w*|sendFile|send_file|FileInputStream|new File)\(\s*[^"')\s][^)]*?\b{_REQ}""", _CODE, False),
    ("idor", S.MEDIUM, "Object lookup by request-supplied id (verify ownership check)", rf"""(?:findById|find_by_id|findOne|get_object_or_404|objects\.get|findByPk)\(\s*[^)]*?\b{_REQ}""", _CODE, False),
]]


def _files(packed: str):
    for block in re.split(r"^=== FILE: ", packed, flags=re.M)[1:]:
        header, _, body = block.partition("\n")
        yield header.rsplit(" (", 1)[0], [ln.split("| ", 1)[-1] for ln in body.splitlines()]


def _manifest(name: str, text: str) -> list[DeepHit]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    lineof = lambda needle: next((i for i, l in enumerate(text.splitlines(), 1) if needle in l), 1)  # noqa: E731
    out = []
    app = root.find("application")
    if app is not None:
        for attr, bad, sev in (("debuggable", "true", S.HIGH), ("allowBackup", "true", S.MEDIUM), ("usesCleartextTraffic", "true", S.MEDIUM)):
            if app.get(_A + attr) == bad:
                out.append(DeepHit(name, lineof(f"android:{attr}"), "android-manifest", sev, f'android:{attr}="true"'))
        comps = [(c.tag, c) for c in app if c.tag in _COMPONENTS]
    else:
        comps = []
    for tag, c in comps:
        guard = c.get(_A + "permission") or c.get(_A + "readPermission") or c.get(_A + "writePermission")
        if c.get(_A + "exported") == "true" and not guard:
            cname = c.get(_A + "name", "?")
            out.append(DeepHit(name, lineof(cname.rsplit(".", 1)[-1]), "android-exported", S.HIGH, f"Exported {tag} {cname} with no permission"))
    return out


def scan_deep(packed: str) -> list[DeepHit]:
    hits: list[DeepHit] = []
    for name, lines in _files(packed):
        if name.endswith("AndroidManifest.xml"):
            hits += _manifest(name, "\n".join(lines))
        text = "\n".join(lines)
        if "setJavaScriptEnabled(true" in text and "addJavascriptInterface" in text:
            ln = next(i for i, l in enumerate(lines, 1) if "addJavascriptInterface" in l)
            hits.append(DeepHit(name, ln, "android-webview", S.HIGH, "WebView enables JavaScript and exposes addJavascriptInterface"))
        for cat, sev, title, pat, exts in _RULES:
            if exts and not name.endswith(exts):
                continue
            if exts is None and not name.endswith(_CODE):
                continue
            for i, l in enumerate(lines, 1):
                if len(l) < 2000 and pat.search(l):
                    hits.append(DeepHit(name, i, cat, sev, title))
    return hits
