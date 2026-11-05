"""Walk a repository and pack it into one line-numbered text blob for the LLM."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import pathspec

IGNORE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env", "__pycache__",
    ".idea", ".vscode", "dist", "build", "target", "out", ".gradle", ".next", ".nuxt",
    "vendor", "Pods", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "coverage",
    "assets", "static", "public", "res", "drawable", "fonts", "images", ".mythos",
}
BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg", ".psd", ".ttf", ".otf",
    ".woff", ".woff2", ".eot", ".mp3", ".mp4", ".wav", ".avi", ".mov", ".webm", ".zip", ".tar",
    ".gz", ".bz2", ".7z", ".rar", ".jar", ".war", ".aar", ".apk", ".aab", ".class", ".dex",
    ".so", ".dll", ".dylib", ".exe", ".o", ".a", ".lib", ".pyc", ".pyo", ".pdf", ".db",
    ".sqlite", ".bin", ".keystore", ".jks", ".lock", ".map", ".min.js", ".min.css",
}
IGNORE_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock",
    "go.sum", "Pipfile.lock", "composer.lock", "gradlew", "gradlew.bat", "MYTHOS_AUDIT.md",
    "mythos.sarif", "MYTHOS_WEB_AUDIT.md", "id_rsa", "id_ed25519", "id_ecdsa",
}
# secret files must never be sent to a third-party API
SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".ppk", ".keystore", ".jks")

# marker file (or suffix) -> stack label; content checks refine some of these
_MARKERS = {
    "build.gradle.kts": "Android/Kotlin/Gradle", "build.gradle": "Android/Java/Gradle",
    "AndroidManifest.xml": "Android", "package.json": "Node.js", "go.mod": "Go",
    "Cargo.toml": "Rust", "pom.xml": "Java/Maven", "requirements.txt": "Python",
    "pyproject.toml": "Python", "Gemfile": "Ruby", "composer.json": "PHP",
    "Dockerfile": "Docker", "Package.swift": "Swift",
}
# (marker file, substring, label)
_REFINE = [
    ("package.json", '"react"', "React"), ("package.json", '"next"', "Next.js"),
    ("package.json", '"express"', "Express"), ("package.json", '"vue"', "Vue"),
    ("requirements.txt", "fastapi", "FastAPI"), ("pyproject.toml", "fastapi", "FastAPI"),
    ("requirements.txt", "django", "Django"), ("pyproject.toml", "django", "Django"),
    ("requirements.txt", "flask", "Flask"), ("pyproject.toml", "flask", "Flask"),
    ("pom.xml", "spring-boot", "Spring Boot"), ("build.gradle", "spring-boot", "Spring Boot"),
    ("build.gradle.kts", "spring-boot", "Spring Boot"),
]


@dataclass
class PackStats:
    files_packed: int = 0
    total_lines: int = 0
    total_chars: int = 0
    est_tokens: int = 0
    skipped_binary: int = 0
    skipped_large: int = 0
    skipped_budget: int = 0
    languages: dict[str, int] = field(default_factory=dict)


@dataclass
class PackResult:
    text: str
    files: list[str]
    stats: PackStats
    stack: list[str]


def detect_stack(root: Path) -> list[str]:
    """Infer the project stack from marker files (searched up to 3 levels deep)."""
    found: dict[str, None] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        depth = Path(dirpath).relative_to(root).parts
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS] if len(depth) < 3 else []
        for name in filenames:
            if name not in _MARKERS and not name.endswith(".csproj"):
                continue
            found[_MARKERS.get(name, ".NET")] = None
            try:
                content = (Path(dirpath) / name).read_text(encoding="utf-8", errors="ignore").lower()
            except OSError:
                continue
            for marker, needle, label in _REFINE:
                if marker == name and needle.lower() in content:
                    found[label] = None
    return list(found)


def _load_gitignore(root: Path) -> pathspec.PathSpec:
    # shortcut: only the root .gitignore is honored, nested ones are not; upgrade if repos need it
    lines: list[str] = []
    gi = root / ".gitignore"
    if gi.is_file():
        lines = gi.read_text(encoding="utf-8", errors="ignore").splitlines()
    return pathspec.PathSpec.from_lines("gitwildmatch", lines)


def _is_binary(path: Path) -> bool:
    if path.suffix.lower() in BINARY_EXTS or path.name.endswith((".min.js", ".min.css")):
        return True
    try:
        with path.open("rb") as fh:
            return b"\0" in fh.read(8192)
    except OSError:
        return True


def pack_codebase(
    root: Path,
    max_chars: int = 3_600_000,  # ~900k tokens at ~4 chars/token, leaves room for the prompt
    max_file_bytes: int = 512_000,
    extra_ignores: list[str] | None = None,
) -> PackResult:
    """Pack all text source files under ``root`` with per-line numbers."""
    root = root.resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"{root} is not a directory")
    spec = _load_gitignore(root)
    extra = pathspec.PathSpec.from_lines("gitwildmatch", extra_ignores or [])
    stats = PackStats()
    parts: list[str] = []
    files: list[str] = []

    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root)
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in IGNORE_DIRS
            and not spec.match_file((rel_dir / d).as_posix() + "/")
            and not extra.match_file((rel_dir / d).as_posix() + "/")
        )
        for name in sorted(filenames):
            rel = (rel_dir / name).as_posix()
            path = Path(dirpath) / name
            if name in IGNORE_FILES or name.startswith(".env") or name.endswith(SECRET_SUFFIXES) or spec.match_file(rel) or extra.match_file(rel):
                continue
            if path.is_symlink():
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if _is_binary(path):
                stats.skipped_binary += 1
                continue
            if size > max_file_bytes:
                stats.skipped_large += 1
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            width = len(str(len(lines)))
            body = "\n".join(f"{i:>{width}}| {ln}" for i, ln in enumerate(lines, 1))
            block = f"=== FILE: {rel} ({len(lines)} lines) ===\n{body}\n\n"
            if stats.total_chars + len(block) > max_chars:
                stats.skipped_budget += 1
                continue
            parts.append(block)
            files.append(rel)
            stats.files_packed += 1
            stats.total_lines += len(lines)
            stats.total_chars += len(block)
            lang = path.suffix.lower() or name
            stats.languages[lang] = stats.languages.get(lang, 0) + len(lines)

    stats.est_tokens = stats.total_chars // 4
    return PackResult("".join(parts), files, stats, detect_stack(root))
