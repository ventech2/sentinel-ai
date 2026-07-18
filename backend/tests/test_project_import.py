"""Tests for GitHub-backed project import metadata."""

import asyncio
from types import SimpleNamespace
from uuid import uuid4

from app.api.routes import projects


def test_project_import_persists_github_default_branch(monkeypatch) -> None:
    user_id = uuid4()
    request = SimpleNamespace(session={"user_id": str(user_id)})

    class CapturingDatabase:
        def __init__(self) -> None:
            self.added = []
            self.commits = 0

        def add(self, value) -> None:
            self.added.append(value)

        async def commit(self) -> None:
            self.commits += 1

        async def refresh(self, _value) -> None:
            return None

    async def github_default_branch(*_args, **kwargs) -> str:
        assert kwargs["owner"] == "octo"
        assert kwargs["repository"] == "legacy-default-branch"
        return "master"

    monkeypatch.setattr(projects, "get_repository_default_branch", github_default_branch)
    database = CapturingDatabase()

    project = asyncio.run(
        projects.create_project(
            projects.ProjectCreate(repo_url="https://github.com/octo/legacy-default-branch"),
            request,
            database,
        )
    )

    assert project.default_branch == "master"
    assert database.added == [project]
    assert database.commits == 1
