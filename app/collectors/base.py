"""
Abstract base class for all WardHound event collectors.

Each real collector (PacketFence syslog, JumpServer API poller, AD event reader,
firewall syslog) subclasses BaseCollector and implements two methods:

  parse_raw()  — turn raw bytes/str/dict from the source into a RawEvent
  normalize()  — turn a RawEvent into a NormalizedEvent

The split between parsing and normalization is intentional: parse_raw() handles
source-system framing (syslog RFC5424, JSON envelope, XML), while normalize()
handles semantic mapping (field renaming, enum translation, entity extraction).
Both are synchronous and pure — no I/O, no side effects — making them trivially
unit-testable in isolation.

Collection I/O (opening sockets, polling REST APIs, reading Windows event logs)
is intentionally out of scope for this base class. Real collectors will add their
own async entry points (e.g., an asyncio UDP listener or an httpx polling loop)
and call parse_raw() + normalize() on each received payload. This keeps the base
interface transport-agnostic and the core transformation logic independently
testable without network access.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from app.schemas.events import NormalizedEvent, RawEvent, SourceSystem


class BaseCollector(ABC):
    """
    Contract that every event collector must fulfill.

    Subclasses must:
      1. Set ``source_system`` to the appropriate SourceSystem member.
      2. Implement ``parse_raw()`` to produce a RawEvent from raw source data.
      3. Implement ``normalize()`` to produce a NormalizedEvent from a RawEvent.

    Subclasses may:
      - Override ``process()`` if they need to short-circuit the two-step flow
        (rare; document the reason in the subclass if done).
      - Add async collection methods (e.g., ``async def listen()``) specific to
        the transport they use (UDP syslog, HTTP polling, WinRM, etc.).
    """

    @property
    @abstractmethod
    def source_system(self) -> SourceSystem:
        """Identifies which enterprise source system this collector handles."""
        ...

    @abstractmethod
    def parse_raw(self, data: bytes | str | dict[str, Any]) -> RawEvent:
        """
        Parse raw input from the source system into a RawEvent.

        Args:
            data: The raw payload as received — bytes for network streams,
                  str for syslog lines or text files, dict for pre-parsed
                  JSON/API responses.

        Returns:
            A RawEvent with source_system, source_host, and raw_payload populated.

        Raises:
            ValueError: If the data cannot be parsed into a valid RawEvent
                        (malformed syslog, unexpected API schema, etc.).
        """
        ...

    @abstractmethod
    def normalize(self, event: RawEvent) -> NormalizedEvent:
        """
        Map a RawEvent to the canonical NormalizedEvent schema.

        Args:
            event: A RawEvent produced by this collector's parse_raw().

        Returns:
            A NormalizedEvent ready for the correlation and risk engines.

        Raises:
            ValueError: If the RawEvent cannot be normalized (unknown event type,
                        missing required fields for this source system, etc.).
        """
        ...

    def process(self, data: bytes | str | dict[str, Any]) -> NormalizedEvent:
        """
        Convenience method: parse raw input and normalize in one call.

        This is the primary entry point for synchronous callers and tests.
        Async transports will typically call parse_raw() and normalize()
        separately inside their own event loops.
        """
        raw = self.parse_raw(data)
        return self.normalize(raw)
