from __future__ import annotations

import json

import httpx
import pytest

from app.collectors.jumpserver_ops import JumpServerOpsClient, clean_job_stdout, parse_pipe_table

TASK_ID = "11111111-2222-3333-4444-555555555555"
HEADER = "mac|computername|pid|category|status"


def test_clean_job_stdout_removes_ansi_ansible_framing_and_nulls() -> None:
    log = (
        "2026-07-17 15:54:23 \x1b[0;33mPF-Example | CHANGED | rc=0 >>\x1b[0m\r\n"
        "\x1b[0;33m1\x1b[0m\r\n"
        f"\x1b[0;33m{HEADER}\x1b[0m\r\n"
        "\x1b[0;33m00:11:22:33:44:55||someuser|Quarantine|unreg\x1b[0m\r\n"
        f"2026-07-17 15:54:24 Task ops.tasks.run_ops_job_execution[{TASK_ID}] "
        "succeeded in 8.2s: None\r\n\x00\x00\x00\r\n"
    )
    assert clean_job_stdout(log) == (f"1\n{HEADER}\n00:11:22:33:44:55||someuser|Quarantine|unreg")


def test_clean_job_stdout_accepts_zero_result() -> None:
    log = (
        "2026-07-17 15:54:23 \x1b[0;33mPF-Example | CHANGED | rc=0 >>\x1b[0m\r\n"
        "\x1b[0;33m0\x1b[0m\r\n"
        f"2026-07-17 15:54:24 Task ops.tasks.run_ops_job_execution[{TASK_ID}] "
        "succeeded in 1.0s: None\r\n\x00\x00"
    )
    assert clean_job_stdout(log) == "0"


def test_parse_pipe_table_is_independent_of_log_cleaning() -> None:
    assert parse_pipe_table(
        f"2\n{HEADER}\n00:11:22:33:44:55||user-a|Quarantine|unreg\n"
        "66:77:88:99:aa:bb||user-b|Quarantine|unreg"
    ) == [
        {
            "mac": "00:11:22:33:44:55",
            "computername": "",
            "pid": "user-a",
            "category": "Quarantine",
            "status": "unreg",
        },
        {
            "mac": "66:77:88:99:aa:bb",
            "computername": "",
            "pid": "user-b",
            "category": "Quarantine",
            "status": "unreg",
        },
    ]
    assert parse_pipe_table("0") == []


@pytest.mark.asyncio
async def test_ops_client_runs_four_endpoint_conversation() -> None:
    requests: list[httpx.Request] = []
    detail_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal detail_calls
        requests.append(request)
        if request.url.path == "/api/v1/assets/assets/":
            assert request.url.params["name"] == "pf-managed-asset"
            return httpx.Response(
                200, json={"results": [{"id": "asset-id", "name": "pf-managed-asset"}]}
            )
        if request.url.path == "/api/v1/ops/jobs/":
            body = json.loads(request.content)
            assert body["assets"] == ["asset-id"]
            assert body["module"] == {"value": "shell", "label": "Shell"}
            assert body["runas"] == "ops-account"
            return httpx.Response(201, json={"task_id": TASK_ID})
        if request.url.path.endswith(f"/task-detail/{TASK_ID}/"):
            detail_calls += 1
            return httpx.Response(
                200,
                json={
                    "is_finished": detail_calls == 2,
                    "status": {"value": "success" if detail_calls == 2 else "running"},
                },
            )
        if request.url.path.endswith(f"/{TASK_ID}/log/"):
            return httpx.Response(200, json={"data": "banner | CHANGED | rc=0 >>\r\n0\r\n"})
        raise AssertionError(request.url)

    async with httpx.AsyncClient(
        base_url="https://jumpserver.example.com", transport=httpx.MockTransport(handler)
    ) as client:
        stdout = await JumpServerOpsClient(client, poll_interval=0).run(
            module="shell",
            args='pfcmd node view category="Quarantine"',
            runas="ops-account",
            asset_name="pf-managed-asset",
            name="test job",
        )

    assert stdout == "0"
    assert len(requests) == 5
