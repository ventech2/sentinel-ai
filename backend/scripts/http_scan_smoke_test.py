"""Trigger and poll a scan through Sentinel's HTTP API only.

Start the API and worker in separate terminals first. For this local fixture
check, start the API with ``INGESTION_LOCAL_REPOSITORY_ROOT`` set to the
absolute ``sample-data/vulnerable-demo-app`` directory (never set that option
in production). Then run this script from ``backend``.

Required environment variables:
    SENTINEL_API_URL         Example: http://127.0.0.1:8000
    SENTINEL_SESSION_COOKIE  Value of the authenticated browser ``session`` cookie

Set one of:
    SENTINEL_PROJECT_ID      Existing project UUID owned by that session
    SENTINEL_REPO_URL        GitHub URL; the script creates a project through the API
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from uuid import UUID

import httpx


async def main() -> None:
    api_url = _required("SENTINEL_API_URL").rstrip("/")
    session_cookie = _required("SENTINEL_SESSION_COOKIE")
    timeout_seconds = 180
    started = time.monotonic()

    async with httpx.AsyncClient(base_url=api_url, cookies={"session": session_cookie}, timeout=15.0) as client:
        project_id = await _project_id(client)
        response = await client.post(f"/projects/{project_id}/scans")
        response.raise_for_status()
        scan = response.json()
        scan_id = scan["id"]
        print(f"Queued scan: {scan_id}")

        while True:
            status_response = await client.get(f"/scans/{scan_id}")
            status_response.raise_for_status()
            status = status_response.json()
            print(f"status={status['status']} files_scanned={status['files_scanned']}")
            if status["status"] in {"complete", "failed"}:
                break
            if time.monotonic() - started > timeout_seconds:
                raise TimeoutError("Timed out waiting for the scan worker.")
            await asyncio.sleep(1.0)

        findings_response = await client.get(f"/scans/{scan_id}/findings")
        findings_response.raise_for_status()
        findings = findings_response.json()
        print(f"final_status={status['status']} findings={len(findings)}")
        for finding in findings:
            print(f"- {finding['severity']}: {finding['title']} ({finding['file_path']}:{finding['line_start']})")
        if status["status"] != "complete":
            raise RuntimeError(status.get("error_message") or "Scan failed.")

        report_response = await client.get(f"/scans/{scan_id}/report")
        report_response.raise_for_status()
        report = report_response.json()
        print(f"risk_score={report['overall_risk_score']}/100")
        print(f"executive_summary={report['summary']}")
        print(f"finding_counts={report['finding_counts']}")


async def _project_id(client: httpx.AsyncClient) -> UUID:
    existing = os.getenv("SENTINEL_PROJECT_ID")
    if existing:
        return UUID(existing)
    repo_url = _required("SENTINEL_REPO_URL")
    response = await client.post("/projects", json={"repo_url": repo_url})
    response.raise_for_status()
    project = response.json()
    print(f"Created project: {project['id']}")
    return UUID(project["id"])


def _required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"Set {name} before running this script.")
    return value


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (httpx.HTTPError, RuntimeError, TimeoutError, ValueError) as error:
        print(f"HTTP scan smoke test failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
