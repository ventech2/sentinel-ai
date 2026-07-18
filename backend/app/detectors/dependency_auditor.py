"""Offline dependency-name checks for likely typosquatting and obscure packages."""

from dataclasses import dataclass
from decimal import Decimal
import json
from pathlib import Path
import re

from app.detectors.file_utils import line_at, line_number_at, read_text_file, relative_path
from app.detectors.models import DetectorFinding

POPULAR_PACKAGES = {
    "react",
    "reactdom",
    "next",
    "express",
    "lodash",
    "axios",
    "typescript",
    "vite",
    "vue",
    "angular",
    "mongoose",
    "jsonwebtoken",
    "bcrypt",
    "dotenv",
    "prisma",
    "tailwindcss",
    "django",
    "flask",
    "fastapi",
    "requests",
    "numpy",
    "pandas",
    "sqlalchemy",
    "pydantic",
    "pytest",
    "celery",
    "redis",
    "cryptography",
    "httpx",
    "uvicorn",
    "gin",
    "mux",
    "cobra",
}
DEPENDENCY_SECTIONS = {"dependencies", "devDependencies", "peerDependencies", "optionalDependencies"}


@dataclass(frozen=True)
class Dependency:
    name: str
    file_path: str
    line_number: int
    snippet: str


def scan_repository(root: Path) -> list[DetectorFinding]:
    """Parse supported manifests under ``root`` without registry lookups."""
    findings: list[DetectorFinding] = []
    for path in root.rglob("package.json"):
        if _is_noise_path(path):
            continue
        contents = read_text_file(path)
        if contents:
            findings.extend(_findings_for_dependencies(_parse_package_json(contents, relative_path(root, path))))
    for path in root.rglob("requirements.txt"):
        if _is_noise_path(path):
            continue
        contents = read_text_file(path)
        if contents:
            findings.extend(_findings_for_dependencies(_parse_requirements(contents, relative_path(root, path))))
    for path in root.rglob("go.mod"):
        if _is_noise_path(path):
            continue
        contents = read_text_file(path)
        if contents:
            findings.extend(_findings_for_dependencies(_parse_go_mod(contents, relative_path(root, path))))
    return findings


def levenshtein_distance(left: str, right: str) -> int:
    """Compute edit distance for the small local reference set."""
    if len(left) < len(right):
        left, right = right, left
    previous = list(range(len(right) + 1))
    for left_index, left_character in enumerate(left, start=1):
        current = [left_index]
        for right_index, right_character in enumerate(right, start=1):
            current.append(
                min(
                    current[-1] + 1,
                    previous[right_index] + 1,
                    previous[right_index - 1] + (left_character != right_character),
                )
            )
        previous = current
    return previous[-1]


def _findings_for_dependencies(dependencies: list[Dependency]) -> list[DetectorFinding]:
    findings: list[DetectorFinding] = []
    for dependency in dependencies:
        closest = _closest_popular_package(dependency.name)
        if closest:
            findings.append(
                DetectorFinding(
                    detector="dependency_audit",
                    category="typosquatted_dependency",
                    severity="high",
                    confidence=Decimal("0.86"),
                    file_path=dependency.file_path,
                    line_start=dependency.line_number,
                    line_end=dependency.line_number,
                    code_snippet=dependency.snippet,
                    title="Dependency name resembles a popular package",
                    description=(
                        f"'{dependency.name}' is a close edit-distance match to '{closest}', "
                        "which can indicate typosquatting."
                    ),
                    fix_suggestion="Verify the package name, publisher, and intended version before installation.",
                )
            )
        elif _looks_obscure(dependency.name):
            findings.append(
                DetectorFinding(
                    detector="dependency_audit",
                    category="unrecognized_dependency",
                    severity="low",
                    confidence=Decimal("0.35"),
                    file_path=dependency.file_path,
                    line_start=dependency.line_number,
                    line_end=dependency.line_number,
                    code_snippet=dependency.snippet,
                    title="Dependency name has a low-recognizability pattern",
                    description=(
                        f"'{dependency.name}' has an unusually random-looking name. This is a local heuristic, "
                        "not a registry reputation check."
                    ),
                    fix_suggestion="Confirm the package source and ownership before depending on it.",
                )
            )
    return findings


def _parse_package_json(contents: str, file_path: str) -> list[Dependency]:
    try:
        payload = json.loads(contents)
    except json.JSONDecodeError:
        return []
    dependencies: list[Dependency] = []
    for section in DEPENDENCY_SECTIONS:
        values = payload.get(section, {})
        if not isinstance(values, dict):
            continue
        for name in values:
            match = re.search(rf'"{re.escape(str(name))}"\s*:', contents)
            line_number = line_number_at(contents, match.start()) if match else 1
            dependencies.append(Dependency(str(name), file_path, line_number, line_at(contents, line_number)))
    return dependencies


def _parse_requirements(contents: str, file_path: str) -> list[Dependency]:
    dependencies: list[Dependency] = []
    for line_number, raw_line in enumerate(contents.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith(("#", "-", "git+", "http://", "https://")):
            continue
        name = re.split(r"[<>=!~;\s\[]", line, maxsplit=1)[0]
        if name:
            dependencies.append(Dependency(name, file_path, line_number, raw_line.strip()[:500]))
    return dependencies


def _parse_go_mod(contents: str, file_path: str) -> list[Dependency]:
    dependencies: list[Dependency] = []
    in_block = False
    for line_number, raw_line in enumerate(contents.splitlines(), start=1):
        line = raw_line.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        candidate = ""
        if line.startswith("require "):
            candidate = line.removeprefix("require ").split()[0]
        elif in_block and line and not line.startswith("//"):
            candidate = line.split()[0]
        if candidate:
            dependencies.append(Dependency(candidate, file_path, line_number, raw_line.strip()[:500]))
    return dependencies


def _closest_popular_package(name: str) -> str | None:
    segments = [_canonicalize(name), _canonicalize(name.rsplit("/", maxsplit=1)[-1])]
    for candidate in segments:
        if not candidate or candidate in POPULAR_PACKAGES:
            continue
        closest = min(POPULAR_PACKAGES, key=lambda popular: levenshtein_distance(candidate, popular))
        if levenshtein_distance(candidate, closest) <= 2:
            return closest
    return None


def _looks_obscure(name: str) -> bool:
    candidate = _canonicalize(name.rsplit("/", maxsplit=1)[-1])
    if len(candidate) < 7 or candidate in POPULAR_PACKAGES:
        return False
    digit_ratio = sum(character.isdigit() for character in candidate) / len(candidate)
    has_vowel = any(character in "aeiou" for character in candidate)
    return digit_ratio >= 0.30 or not has_vowel


def _canonicalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _is_noise_path(path: Path) -> bool:
    return any(part in {".git", "node_modules", "venv", ".venv", "__pycache__"} for part in path.parts)
