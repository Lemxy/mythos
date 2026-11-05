"""Gemini call returning a validated MythosAuditReport."""

from __future__ import annotations

import json
import os

from pydantic import ValidationError

from .prompts import SYSTEM_PROMPT, WEB_SYSTEM_PROMPT, build_user_prompt, build_web_prompt
from .schema import MythosAuditReport, WebAuditReport

DEFAULT_MODEL = os.environ.get("MYTHOS_MODEL", "gemini-3.1-pro-preview")


class GeminiError(RuntimeError):
    """Raised when the model call fails or returns unusable output."""


class GeminiQuotaError(GeminiError):
    """Raised on HTTP 429 / RESOURCE_EXHAUSTED / quota errors so the caller can fall back to local Claude."""


def _is_quota(exc: Exception) -> bool:
    msg = str(exc).lower()
    return getattr(exc, "code", None) == 429 or any(k in msg for k in ("429", "resource_exhausted", "quota"))


def _parse(text: str | None, model_cls=MythosAuditReport):
    if not text:
        raise GeminiError("Gemini returned an empty response (possibly blocked or truncated).")
    text = text.strip()
    if text.startswith("```"):  # fallback path may wrap JSON in a fence
        text = text.strip("`").removeprefix("json").strip()
    try:
        return model_cls.model_validate_json(text)
    except (ValidationError, json.JSONDecodeError) as exc:
        raise GeminiError(f"Gemini output did not match the report schema: {exc}") from exc


def _generate(api_key: str, system: str, contents: str, model: str, schema):
    """Schema-constrained Gemini call; plain-JSON fallback if the SDK rejects the schema."""
    try:
        from google import genai
        from google.genai import types
    except ImportError as exc:
        raise GeminiError("google-genai is not installed. Run: pip install google-genai") from exc

    client = genai.Client(api_key=api_key)

    def call(config: "types.GenerateContentConfig"):
        return client.models.generate_content(model=model, contents=contents, config=config)

    base = dict(system_instruction=system, temperature=0.1, response_mime_type="application/json")
    try:
        resp = call(types.GenerateContentConfig(**base, response_schema=schema))
    except Exception as first:  # SDK/schema-version quirks: retry once without response_schema
        if _is_quota(first):
            raise GeminiQuotaError(f"Gemini quota exhausted: {first}") from first
        schema_hint = json.dumps(schema.model_json_schema())
        fallback = dict(base, system_instruction=f"{system}\nJSON Schema:\n{schema_hint}")
        try:
            resp = call(types.GenerateContentConfig(**fallback))
        except Exception as second:
            if _is_quota(second):
                raise GeminiQuotaError(f"Gemini quota exhausted: {second}") from second
            raise GeminiError(f"Gemini request failed: {second} (first attempt: {first})") from second

    parsed = getattr(resp, "parsed", None)
    if isinstance(parsed, schema):
        return parsed
    return _parse(resp.text, schema)


def run_audit(
    api_key: str,
    packed: str,
    stack: list[str],
    secret_hints: str = "",
    model: str = DEFAULT_MODEL,
) -> MythosAuditReport:
    """Send the packed repo to Gemini for a source-code audit."""
    return _generate(api_key, SYSTEM_PROMPT, build_user_prompt(packed, stack, secret_hints), model, MythosAuditReport)


def run_web_audit(api_key: str, web_data, model: str = DEFAULT_MODEL) -> WebAuditReport:
    """Analyze a WebAuditData scan of a live site into a structured DAST report."""
    return _generate(api_key, WEB_SYSTEM_PROMPT, build_web_prompt(web_data.model_dump_json(indent=1)), model, WebAuditReport)
