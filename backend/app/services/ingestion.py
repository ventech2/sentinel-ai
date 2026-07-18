"""OAuth-authorized repository cloning and inventory for explicitly selected scan jobs."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Callable
from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.detectors.file_utils import NOISE_DIRECTORIES, iter_text_files, relative_path
from app.services.github_repository import (
    GitHubRepositoryClient,
    GitHubRepositoryError,
    get_repository_access_token,
    get_repository_default_branch,
)

if TYPE_CHECKING:
    from app.models.project import Project


GITHUB_GIT_ROOT = "https://github.com"
REPOSITORY_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]+$")
LANGUAGES_BY_EXTENSION = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".java": "Java",
    ".rb": "Ruby",
    ".php": "PHP",
    ".rs": "Rust",
    ".cs": "C#",
    ".json": "JSON",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".toml": "TOML",
    ".tf": "Terraform",
    ".dockerfile": "Dockerfile",
}


class IngestionError(RuntimeError):
    """A repository could not be cloned or safely inventoried."""


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    """Temporary repository copy and its lightweight inventory."""

    root: Path
    commit_sha: str
    files: tuple[str, ...]
    languages: dict[str, int]
    total_bytes: int
    cleanup_when_done: bool = True

    @property
    def files_scanned(self) -> int:
        return len(self.files)


class RepositoryIngestionService:
    """Clone one explicitly selected GitHub project with its owner's OAuth credential."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        metadata_client: GitHubRepositoryClient | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._metadata_client = metadata_client or GitHubRepositoryClient()

    async def ingest(
        self,
        db: AsyncSession,
        project: Project,
        *,
        use_local_override: bool = True,
    ) -> RepositorySnapshot:
        """Materialize one selected repository and enforce the configured size cap.

        ``use_local_override`` exists only for the development HTTP smoke test.
        Remediation deliberately disables it so a requested fix is prepared
        against the selected GitHub project and its stored OAuth credential.
        """
        if use_local_override and self.settings.ingestion_local_repository_root is not None:
            if self.settings.environment.lower() == "production":
                raise IngestionError("Local repository ingestion is disabled in production.")
            return await asyncio.to_thread(self._copy_local_repository, self.settings.ingestion_local_repository_root)

        await self._refresh_default_branch(db, project)
        token = await self._project_access_token(db, project)
        # This function receives one persisted Project chosen by the current
        # user. It never lists or probes other repositories on the token.
        # GitHub's clone response is the access boundary for that exact repo.
        return await asyncio.to_thread(self._clone_repository, project, token)

    def cleanup(self, snapshot: RepositorySnapshot) -> None:
        """Remove an ingestion-owned temporary clone after it has been used.

        Do not silently ignore a failed deletion: a failed cleanup should be
        visible to the caller's logger so local clone directories cannot grow
        without notice. The directory-shape check keeps this helper from ever
        removing a caller-owned repository snapshot.
        """
        if not snapshot.cleanup_when_done:
            return

        root = snapshot.root.resolve()
        parent = root.parent
        if root.name != "repository" or not parent.name.startswith(("sentinel-scan-", "sentinel-local-scan-")):
            raise IngestionError("Refusing to clean a repository snapshot not owned by Sentinel ingestion.")

        # Windows can briefly retain a Git file handle immediately after clone
        # or worktree removal. Retry once, then surface the failure to the
        # caller rather than silently leaking the directory.
        last_error: OSError | None = None
        for attempt in range(2):
            try:
                shutil.rmtree(parent, onerror=_clear_readonly_and_retry)
                return
            except OSError as error:
                last_error = error
                if attempt == 0:
                    time.sleep(0.1)
        raise IngestionError(f"Unable to clean temporary repository snapshot: {last_error}")

    async def _project_access_token(self, db: AsyncSession, project: Project) -> str:
        try:
            return await get_repository_access_token(db, user_id=project.user_id, settings=self.settings)
        except GitHubRepositoryError as error:
            raise IngestionError(str(error)) from error

    async def _refresh_default_branch(self, db: AsyncSession, project: Project) -> str:
        """Refresh legacy imports before clone, then use the persisted branch."""
        try:
            default_branch = await get_repository_default_branch(
                db,
                user_id=project.user_id,
                owner=project.repo_owner,
                repository=project.repo_name,
                settings=self.settings,
                client=self._metadata_client,
            )
        except GitHubRepositoryError as error:
            raise IngestionError(f"Unable to resolve the repository default branch: {error}") from error
        project.default_branch = default_branch
        await db.flush()
        return project.default_branch

    def _clone_repository(self, project: Project, access_token: str) -> RepositorySnapshot:
        remote_url = _github_remote_url(project.repo_owner, project.repo_name)
        parent = Path(tempfile.mkdtemp(prefix="sentinel-scan-"))
        destination = parent / "repository"
        try:
            result = subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "--filter=blob:none",
                    "--branch",
                    project.default_branch,
                    remote_url,
                    str(destination),
                ],
                capture_output=True,
                text=True,
                timeout=self.settings.ingestion_clone_timeout_seconds,
                env=_git_auth_environment(access_token),
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            shutil.rmtree(parent, ignore_errors=True)
            raise IngestionError("Repository clone timed out.") from error
        except OSError as error:
            shutil.rmtree(parent, ignore_errors=True)
            raise IngestionError(f"Unable to start repository clone: {error}") from error
        if result.returncode != 0:
            detail = _scrub_token((result.stderr or result.stdout).strip(), access_token)
            shutil.rmtree(parent, ignore_errors=True)
            raise IngestionError(f"Repository clone failed: {detail or 'Git rejected the clone.'}")
        try:
            return _inventory_repository(destination, self.settings.ingestion_max_repository_bytes, cleanup_when_done=True)
        except Exception:
            shutil.rmtree(parent, ignore_errors=True)
            raise

    def _copy_local_repository(self, source: Path) -> RepositorySnapshot:
        source = source.resolve()
        if not source.is_dir():
            raise IngestionError("Configured local ingestion root does not exist.")
        parent = Path(tempfile.mkdtemp(prefix="sentinel-local-scan-"))
        destination = parent / "repository"
        try:
            shutil.copytree(source, destination, ignore=shutil.ignore_patterns(*NOISE_DIRECTORIES))
            return _inventory_repository(destination, self.settings.ingestion_max_repository_bytes, cleanup_when_done=True)
        except Exception:
            shutil.rmtree(parent, ignore_errors=True)
            raise


def inventory_existing_repository(root: Path, *, max_bytes: int = 500 * 1024 * 1024) -> RepositorySnapshot:
    """Inventory an injected test fixture without taking ownership of its directory."""
    return _inventory_repository(root, max_bytes, cleanup_when_done=False)


def _inventory_repository(root: Path, max_bytes: int, *, cleanup_when_done: bool) -> RepositorySnapshot:
    root = root.resolve()
    total_bytes = _repository_size(root)
    if total_bytes > max_bytes:
        raise IngestionError(f"Repository exceeds the {max_bytes // (1024 * 1024)}MB scan limit.")
    files = tuple(relative_path(root, path) for path in iter_text_files(root))
    languages: dict[str, int] = {}
    for file_path in files:
        suffix = Path(file_path).suffix.lower()
        language = LANGUAGES_BY_EXTENSION.get(suffix)
        if language:
            languages[language] = languages.get(language, 0) + 1
    return RepositorySnapshot(
        root=root,
        commit_sha=_commit_sha(root),
        files=files,
        languages=languages,
        total_bytes=total_bytes,
        cleanup_when_done=cleanup_when_done,
    )


def _repository_size(root: Path) -> int:
    total = 0
    for path in root.rglob("*"):
        if not path.is_file() or any(part in NOISE_DIRECTORIES for part in path.parts):
            continue
        try:
            total += path.stat().st_size
        except OSError:
            continue
    return total


def _commit_sha(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else "local-fixture"


def _github_remote_url(owner: str, repository: str) -> str:
    if not REPOSITORY_COMPONENT.fullmatch(owner) or not REPOSITORY_COMPONENT.fullmatch(repository):
        raise IngestionError("Project has an invalid GitHub repository owner or name.")
    return f"{GITHUB_GIT_ROOT}/{owner}/{repository}.git"


def _git_auth_environment(access_token: str) -> dict[str, str]:
    encoded = base64.b64encode(f"x-access-token:{access_token}".encode("utf-8")).decode("ascii")
    environment = os.environ.copy()
    for key in tuple(environment):
        if key.startswith("GIT_CONFIG_"):
            environment.pop(key, None)
    environment.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.extraHeader",
            "GIT_CONFIG_VALUE_0": f"Authorization: Basic {encoded}",
        }
    )
    return environment


def _scrub_token(message: str, access_token: str) -> str:
    return message.replace(access_token, "[redacted]")[:500]


def _clear_readonly_and_retry(function: Callable[[str], object], path: str, _: object) -> None:
    """Allow cleanup of read-only Git object files in a verified temp clone."""
    os.chmod(path, stat.S_IWRITE)
    function(path)
