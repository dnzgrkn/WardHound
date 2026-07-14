from __future__ import annotations

import threading
from typing import Any

import pytest
from ldap3 import MOCK_SYNC, Connection, Server
from ldap3.core.exceptions import LDAPSocketOpenError

from app.integrations.active_directory import (
    AD_ACCOUNTDISABLE,
    ActiveDirectoryClient,
    ActiveDirectoryError,
)

BIND_DN = "CN=svc-wardhound,OU=Service Accounts,DC=corp,DC=example,DC=com"
USER_DN = "CN=jdoe,OU=Users,DC=corp,DC=example,DC=com"
SEARCH_BASE = "OU=Users,DC=corp,DC=example,DC=com"


def mock_connection(
    *, user_control: int | None = 512, bind_password: str = "synthetic-bind-password"
) -> Connection:
    connection = Connection(
        Server("dc01.corp.example.com"),
        user=BIND_DN,
        password=bind_password,
        client_strategy=MOCK_SYNC,
    )
    connection.strategy.add_entry(
        BIND_DN,
        {"objectClass": ["person"], "userPassword": "synthetic-bind-password"},
    )
    if user_control is not None:
        connection.strategy.add_entry(
            USER_DN,
            {
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "sAMAccountName": "jdoe",
                "userAccountControl": user_control,
            },
        )
    return connection


def client(connection: Connection) -> ActiveDirectoryClient:
    return ActiveDirectoryClient(
        "ldaps://dc01.corp.example.com:636",
        BIND_DN,
        "synthetic-bind-password",
        SEARCH_BASE,
        connection=connection,
    )


async def test_disable_user_sets_bit_and_confirms_result_off_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = mock_connection()
    event_loop_thread = threading.get_ident()
    ldap_threads: list[int] = []
    original_search = connection.search

    def tracking_search(*args: Any, **kwargs: Any) -> bool:
        ldap_threads.append(threading.get_ident())
        return bool(original_search(*args, **kwargs))

    monkeypatch.setattr(connection, "search", tracking_search)

    result = await client(connection).disable_user("jdoe")

    assert result.already_disabled is False
    assert len(ldap_threads) == 2
    assert all(thread_id != event_loop_thread for thread_id in ldap_threads)
    assert int(connection.strategy.entries[USER_DN]["userAccountControl"][0]) & AD_ACCOUNTDISABLE


async def test_disable_user_is_idempotent_when_already_disabled() -> None:
    connection = mock_connection(user_control=514)

    result = await client(connection).disable_user("jdoe")

    assert result.already_disabled is True
    assert int(connection.strategy.entries[USER_DN]["userAccountControl"][0]) == 514


async def test_disable_user_reports_user_not_found() -> None:
    with pytest.raises(ActiveDirectoryError, match="user was not found"):
        await client(mock_connection(user_control=None)).disable_user("jdoe")


async def test_disable_user_reports_bind_failure_without_password() -> None:
    connection = mock_connection(bind_password="wrong-synthetic-password")

    with pytest.raises(ActiveDirectoryError, match="bind failed") as caught:
        await client(connection).disable_user("jdoe")

    assert "synthetic-bind-password" not in str(caught.value)
    assert "wrong-synthetic-password" not in str(caught.value)


async def test_disable_user_rejects_unconfirmed_modify(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = mock_connection()
    monkeypatch.setattr(connection, "modify", lambda *args, **kwargs: True)

    with pytest.raises(ActiveDirectoryError, match="did not show the account disabled"):
        await client(connection).disable_user("jdoe")


async def test_disable_user_reports_modify_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = mock_connection()
    monkeypatch.setattr(connection, "modify", lambda *args, **kwargs: False)

    with pytest.raises(ActiveDirectoryError, match="account modify failed"):
        await client(connection).disable_user("jdoe")


async def test_disable_user_reports_connection_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = mock_connection()

    def fail_bind() -> bool:
        raise LDAPSocketOpenError("synthetic connection failure")

    monkeypatch.setattr(connection, "bind", fail_bind)

    with pytest.raises(ActiveDirectoryError, match="connection failed"):
        await client(connection).disable_user("jdoe")


def test_client_rejects_unencrypted_ldap_url() -> None:
    with pytest.raises(ValueError, match="must use ldaps"):
        ActiveDirectoryClient(
            "ldap://dc01.corp.example.com:389",
            BIND_DN,
            "synthetic-bind-password",
            SEARCH_BASE,
        )
