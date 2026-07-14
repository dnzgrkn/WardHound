"""Async boundary for the synchronous ldap3 Active Directory client."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from ldap3 import BASE, MODIFY_REPLACE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

AD_ACCOUNTDISABLE = 0x2
AD_LDAP_TIMEOUT_SECONDS = 10.0


class ActiveDirectoryError(RuntimeError):
    """Raised when Active Directory cannot confirm the requested account state."""


@dataclass(frozen=True)
class DisableAccountResult:
    """Safe confirmation details for an account-disable audit record."""

    already_disabled: bool


class ActiveDirectoryClient:
    """Ensure one on-premises Active Directory user account is disabled."""

    def __init__(
        self,
        ldap_url: str,
        bind_dn: str,
        bind_password: str,
        search_base_dn: str,
        *,
        timeout: float = AD_LDAP_TIMEOUT_SECONDS,
        connection: Connection | None = None,
    ) -> None:
        parsed_url = urlsplit(ldap_url)
        if parsed_url.scheme.casefold() != "ldaps" or parsed_url.hostname is None:
            raise ValueError("Active Directory LDAP URL must use ldaps://")
        self._search_base_dn = search_base_dn
        if connection is None:
            try:
                server = Server(
                    ldap_url,
                    tls=Tls(validate=ssl.CERT_REQUIRED),
                    connect_timeout=timeout,
                )
                connection = Connection(
                    server,
                    user=bind_dn,
                    password=bind_password,
                    receive_timeout=timeout,
                )
            except LDAPException as exc:
                raise ActiveDirectoryError(
                    "Active Directory connection configuration failed"
                ) from exc
        self._connection = connection

    async def disable_user(self, sam_account_name: str) -> DisableAccountResult:
        """Run the complete blocking LDAP transaction outside the event loop."""
        return await asyncio.to_thread(self._disable_user_sync, sam_account_name)

    def _disable_user_sync(self, sam_account_name: str) -> DisableAccountResult:
        connection = self._connection
        try:
            if not connection.bind():
                raise ActiveDirectoryError("Active Directory bind failed")
            user_dn, current_control = self._find_user(connection, sam_account_name)
            if current_control & AD_ACCOUNTDISABLE:
                return DisableAccountResult(already_disabled=True)

            disabled_control = current_control | AD_ACCOUNTDISABLE
            if not connection.modify(  # type: ignore[no-untyped-call]
                user_dn,
                {"userAccountControl": [(MODIFY_REPLACE, [disabled_control])]},
            ):
                raise ActiveDirectoryError(
                    f"Active Directory account modify failed with result code "
                    f"{_result_code(connection)}"
                )

            confirmed_control = self._read_user_account_control(connection, user_dn)
            if not confirmed_control & AD_ACCOUNTDISABLE:
                raise ActiveDirectoryError(
                    "Active Directory confirmation read did not show the account disabled"
                )
            return DisableAccountResult(already_disabled=False)
        except ActiveDirectoryError:
            raise
        except (LDAPException, OSError) as exc:
            raise ActiveDirectoryError("Active Directory connection failed") from exc
        finally:
            with contextlib.suppress(LDAPException, OSError):
                connection.unbind()  # type: ignore[no-untyped-call]

    def _find_user(self, connection: Connection, sam_account_name: str) -> tuple[str, int]:
        found = connection.search(
            search_base=self._search_base_dn,
            search_filter=(
                "(&(objectClass=user)"
                f"(sAMAccountName={escape_filter_chars(sam_account_name)}))"
            ),
            search_scope=SUBTREE,
            attributes=["userAccountControl"],
            size_limit=2,
        )
        entries = _search_entries(connection) if found else []
        if not entries:
            raise ActiveDirectoryError("Active Directory user was not found")
        if len(entries) > 1:
            raise ActiveDirectoryError("Active Directory user lookup was ambiguous")
        entry = entries[0]
        dn = entry.get("dn")
        if not isinstance(dn, str) or not dn:
            raise ActiveDirectoryError("Active Directory user response had no DN")
        return dn, _user_account_control(entry)

    def _read_user_account_control(self, connection: Connection, user_dn: str) -> int:
        found = connection.search(
            search_base=user_dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["userAccountControl"],
            size_limit=1,
        )
        entries = _search_entries(connection) if found else []
        if len(entries) != 1:
            raise ActiveDirectoryError("Active Directory confirmation read failed")
        return _user_account_control(entries[0])


def _search_entries(connection: Connection) -> list[dict[str, object]]:
    response = connection.response or []
    return [
        entry
        for entry in response
        if isinstance(entry, dict) and entry.get("type") == "searchResEntry"
    ]


def _user_account_control(entry: Mapping[str, object]) -> int:
    attributes = entry.get("attributes")
    if not isinstance(attributes, Mapping):
        raise ActiveDirectoryError("Active Directory user response had no attributes")
    value = attributes.get("userAccountControl")
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ActiveDirectoryError(
            "Active Directory userAccountControl was invalid"
        ) from exc


def _result_code(connection: Connection) -> object:
    result = connection.result
    return result.get("result", "unknown") if isinstance(result, dict) else "unknown"
