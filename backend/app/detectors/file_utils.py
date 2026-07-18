"""Safe text-file iteration helpers shared by static detectors."""

from collections.abc import Iterator
from pathlib import Path

NOISE_DIRECTORIES = {".git", "node_modules", "venv", ".venv", "__pycache__"}
MAX_TEXT_FILE_BYTES = 1_000_000


def iter_text_files(root: Path) -> Iterator[Path]:
    """Yield readable repository files while avoiding binaries and scan noise."""
    root = root.resolve()
    for path in root.rglob("*"):
        if not path.is_file() or any(part in NOISE_DIRECTORIES for part in path.parts):
            continue
        try:
            if path.stat().st_size > MAX_TEXT_FILE_BYTES or _is_binary(path):
                continue
        except OSError:
            continue
        yield path


def read_text_file(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def relative_path(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def line_at(contents: str, line_number: int) -> str:
    lines = contents.splitlines()
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1].strip()[:500]
    return ""


def line_number_at(contents: str, offset: int) -> int:
    return contents.count("\n", 0, offset) + 1


def _is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as file:
            return b"\x00" in file.read(8192)
    except OSError:
        return True
