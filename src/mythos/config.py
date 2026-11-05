"""API key discovery and persistence."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import dotenv_values

KEY_NAME = "GEMINI_API_KEY"
KEY_URL = "https://aistudio.google.com/apikey"
USER_ENV = Path.home() / ".mythos" / ".env"


class MissingApiKeyError(RuntimeError):
    """Raised when no Gemini API key can be found or obtained."""


def get_gemini_api_key() -> str | None:
    """Look up the key in: process env, ./.env, then ~/.mythos/.env."""
    if key := os.environ.get(KEY_NAME):
        return key.strip()
    for path in (Path.cwd() / ".env", USER_ENV):
        if path.is_file() and (key := dotenv_values(path).get(KEY_NAME)):
            return key.strip()
    return None


def save_gemini_api_key(key: str) -> Path:
    """Persist the key to ~/.mythos/.env (owner-only perms where supported)."""
    USER_ENV.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    if USER_ENV.is_file():
        lines = [
            ln for ln in USER_ENV.read_text(encoding="utf-8").splitlines()
            if not ln.startswith(f"{KEY_NAME}=")
        ]
    lines.append(f'{KEY_NAME}="{key.strip()}"')
    USER_ENV.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        USER_ENV.chmod(0o600)
    except OSError:  # shortcut: best-effort on Windows, ACLs are not touched
        pass
    return USER_ENV


def ensure_gemini_api_key(interactive: bool = True) -> str:
    """Return a key, prompting the user to create and save one if allowed."""
    if key := get_gemini_api_key():
        return key
    if not interactive:
        raise MissingApiKeyError(
            f"{KEY_NAME} not found. Set it in the environment, a .env file, or run `mythos setup`."
        )
    import typer

    typer.echo(f"\nMythos needs a Gemini API key. Get a free one at {KEY_URL}\n")
    key = typer.prompt("Paste your Gemini API key", hide_input=True).strip()
    if not key:
        raise MissingApiKeyError("No API key entered.")
    path = save_gemini_api_key(key)
    os.environ[KEY_NAME] = key
    typer.echo(f"Saved to {path}")
    return key
