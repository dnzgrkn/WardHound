"""Generic client for audited command execution through JumpServer Ops jobs."""

from __future__ import annotations

import asyncio
import re
from time import monotonic
from typing import Any

import httpx

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ANSIBLE_BANNER = re.compile(r"^.*\|\s+(?:CHANGED|SUCCESS|FAILED|UNREACHABLE)\s+\|.*>>\s*$")
_TASK_STATUS = re.compile(r"^.*Task\s+.+\[(?:[^\]]+)\]\s+(?:succeeded|failed)\b.*$")


def clean_job_stdout(log_data: str) -> str:
    """Remove JumpServer/Ansible framing and return only command stdout."""
    cleaned = _ANSI_ESCAPE.sub("", log_data.replace("\x00", ""))
    lines = cleaned.replace("\r\n", "\n").replace("\r", "\n").splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    if lines and _ANSIBLE_BANNER.match(lines[0]):
        lines.pop(0)
    while lines and (not lines[-1].strip() or _TASK_STATUS.match(lines[-1])):
        lines.pop()
    return "\n".join(lines).strip()


def parse_pipe_table(stdout: str) -> list[dict[str, str]]:
    """Parse pfcmd-style count/header/pipe rows, including a valid zero result."""
    lines = [line for line in stdout.splitlines() if line.strip()]
    if not lines:
        raise ValueError("Command output is missing its result count")
    try:
        count = int(lines[0].strip())
    except ValueError as exc:
        raise ValueError("Command output result count must be an integer") from exc
    if count == 0:
        return []
    if count < 0 or len(lines) < 2:
        raise ValueError("Command output is missing its pipe-delimited header")
    header = lines[1].split("|")
    rows = lines[2:]
    if len(rows) != count:
        raise ValueError(f"Command output declared {count} records but contained {len(rows)}")
    records: list[dict[str, str]] = []
    for row in rows:
        values = row.split("|")
        if len(values) != len(header):
            raise ValueError("Command output row does not match its header")
        records.append(dict(zip(header, values, strict=True)))
    return records


class JumpServerOpsClient:
    """Run generic instant jobs through JumpServer's audited Ops Job API."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        completion_timeout: float = 60.0,
        poll_interval: float = 1.0,
    ) -> None:
        self.client = client
        self.completion_timeout = completion_timeout
        self.poll_interval = poll_interval

    async def resolve_asset_id(self, asset_name: str) -> str:
        response = await self.client.get("/api/v1/assets/assets/", params={"name": asset_name})
        response.raise_for_status()
        body: Any = response.json()
        results = body.get("results") if isinstance(body, dict) else body
        if not isinstance(results, list):
            raise ValueError("JumpServer asset lookup must return a list")
        matches = [
            item for item in results if isinstance(item, dict) and item.get("name") == asset_name
        ]
        if len(matches) != 1 or not isinstance(matches[0].get("id"), str):
            raise ValueError(
                f"JumpServer asset name must resolve to exactly one asset: {asset_name!r}"
            )
        return str(matches[0]["id"])

    async def run(self, *, module: str, args: str, runas: str, asset_name: str, name: str) -> str:
        asset_id = await self.resolve_asset_id(asset_name)
        response = await self.client.post(
            "/api/v1/ops/jobs/",
            json={
                "name": name,
                "type": {"value": "adhoc", "label": "Adhoc"},
                "module": {"value": module, "label": module.title()},
                "args": args,
                "assets": [asset_id],
                "runas_policy": {"value": "skip", "label": "Skip"},
                "runas": runas,
                "instant": True,
                "is_periodic": False,
                "run_after_save": True,
            },
        )
        response.raise_for_status()
        task_id = response.json().get("task_id")
        if not isinstance(task_id, str) or not task_id:
            raise ValueError("JumpServer Ops job response is missing task_id")
        await self._wait_for_completion(task_id)
        log_response = await self.client.get(f"/api/v1/ops/ansible/job-execution/{task_id}/log/")
        log_response.raise_for_status()
        log_data = log_response.json().get("data")
        if not isinstance(log_data, str):
            raise ValueError("JumpServer Ops job log is missing string data")
        return clean_job_stdout(log_data)

    async def _wait_for_completion(self, task_id: str) -> None:
        deadline = monotonic() + self.completion_timeout
        while True:
            response = await self.client.get(f"/api/v1/ops/job-execution/task-detail/{task_id}/")
            response.raise_for_status()
            body = response.json()
            if body.get("is_finished") is True:
                status = body.get("status")
                value = status.get("value") if isinstance(status, dict) else None
                if value != "success":
                    raise RuntimeError(f"JumpServer Ops job finished with status {value!r}")
                return
            if monotonic() >= deadline:
                raise TimeoutError(f"JumpServer Ops job {task_id} did not finish in time")
            await asyncio.sleep(self.poll_interval)
