"""Open one real PR for a detected hardcoded secret in a disposable repository.

Run from ``backend`` after creating a test repository and a local clone. This
script deliberately uses a token environment variable only for a manual smoke
test; production remediation uses the encrypted ``oauth_tokens`` record.

Required environment variables:
    GITHUB_TOKEN                 OAuth/PAT with repository contents + pull-request access
    GITHUB_REPO_OWNER            GitHub owner of the disposable repository
    GITHUB_REPO_NAME             Repository name
    REMEDIATION_REPOSITORY_ROOT  Absolute path to its local clone

Optional:
    GITHUB_DEFAULT_BRANCH=main
"""

import asyncio
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from uuid import uuid4

# Permit ``python scripts/github_pr_smoke_test.py`` from the backend directory.
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.detectors.secret_scanner import scan_repository
from app.remediation.fix_generator import generate_fix
from app.remediation.github_pr import (
    create_github_pull_request,
    prepare_isolated_branch,
    push_prepared_branch,
)
from app.remediation.verifier import verify_proposal


def main() -> None:
    token = _required("GITHUB_TOKEN")
    project = SimpleNamespace(
        repo_owner=_required("GITHUB_REPO_OWNER"),
        repo_name=_required("GITHUB_REPO_NAME"),
        default_branch=os.getenv("GITHUB_DEFAULT_BRANCH", "main"),
    )
    root = Path(_required("REMEDIATION_REPOSITORY_ROOT")).resolve()
    finding = next(
        (item for item in scan_repository(root) if item.category == "hardcoded_secret"),
        None,
    )
    if finding is None:
        raise SystemExit("No hardcoded secret was detected in the configured repository.")
    proposal = generate_fix(finding, root)
    if not proposal.has_changes:
        raise SystemExit(f"No safe Tier 1 patch was generated: {proposal.guidance}")
    verification = verify_proposal(proposal)
    if not verification["valid"]:
        raise SystemExit(f"Generated patch did not pass syntax verification: {verification}")

    scan_id, finding_id = uuid4(), uuid4()
    branch = prepare_isolated_branch(
        root,
        default_branch=project.default_branch,
        scan_id=scan_id,
        finding_id=finding_id,
        changes=proposal.changes,
    )
    push_prepared_branch(branch, project, token)
    pr_url = asyncio.run(
        create_github_pull_request(
            project=project,
            finding=finding,
            branch=branch,
            access_token=token,
        )
    )
    print(f"Finding: {finding.title} ({finding.file_path}:{finding.line_start})")
    print(f"Syntax verification: {verification}")
    print(f"Branch: {branch.name}")
    print(f"Pull request opened: {pr_url}")


def _required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"Set {name} before running this script.")
    return value


if __name__ == "__main__":
    main()
