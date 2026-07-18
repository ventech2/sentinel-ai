"""Tests for safe ownership and cleanup of temporary repository snapshots."""

import asyncio
from pathlib import Path
import stat
from types import SimpleNamespace

from app.services.ingestion import RepositoryIngestionService, RepositorySnapshot


def test_cleanup_removes_an_ingestion_owned_snapshot(tmp_path: Path) -> None:
    """Temporary clones used by scans/remediations must not accumulate."""
    parent = tmp_path / "sentinel-scan-owned"
    root = parent / "repository"
    root.mkdir(parents=True)
    file_path = root / "app.py"
    file_path.write_text("print('ok')\n", encoding="utf-8")
    file_path.chmod(stat.S_IREAD)
    snapshot = RepositorySnapshot(
        root=root,
        commit_sha="test",
        files=("app.py",),
        languages={"Python": 1},
        total_bytes=12,
        cleanup_when_done=True,
    )

    RepositoryIngestionService().cleanup(snapshot)

    assert not parent.exists()


def test_ingestion_refreshes_and_clones_the_github_default_master_branch(tmp_path: Path, monkeypatch) -> None:
    """A repository whose default branch is master must never be cloned as main."""
    project = SimpleNamespace(
        user_id="user-id",
        repo_owner="octo",
        repo_name="legacy-default-branch",
        default_branch="main",
    )
    snapshot = RepositorySnapshot(
        root=tmp_path,
        commit_sha="master-sha",
        files=(),
        languages={},
        total_bytes=0,
        cleanup_when_done=False,
    )
    observed: dict[str, object] = {}

    class FakeDatabase:
        async def flush(self) -> None:
            observed["flushed"] = True

    async def resolve_default_branch(*_args, **kwargs) -> str:
        observed["metadata_owner"] = kwargs["owner"]
        observed["metadata_repository"] = kwargs["repository"]
        return "master"

    async def access_token(*_args, **_kwargs) -> str:
        return "token"

    def clone(clone_project, _token: str) -> RepositorySnapshot:
        observed["clone_branch"] = clone_project.default_branch
        return snapshot

    service = RepositoryIngestionService()
    monkeypatch.setattr("app.services.ingestion.get_repository_default_branch", resolve_default_branch)
    monkeypatch.setattr("app.services.ingestion.get_repository_access_token", access_token)
    monkeypatch.setattr(service, "_clone_repository", clone)

    result = asyncio.run(service.ingest(FakeDatabase(), project))

    assert result is snapshot
    assert project.default_branch == "master"
    assert observed == {
        "metadata_owner": "octo",
        "metadata_repository": "legacy-default-branch",
        "flushed": True,
        "clone_branch": "master",
    }
