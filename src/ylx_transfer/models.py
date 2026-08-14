from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class SourceKind(StrEnum):
    DEVICE = "device"
    MEDIA = "media"


class Availability(StrEnum):
    ONLINE = "online"
    OFFLINE = "offline"


@dataclass(frozen=True, slots=True)
class SourceLocation:
    location: str
    availability: Availability
    last_seen_at: str


@dataclass(frozen=True, slots=True)
class SourceRecord:
    source_id: str
    kind: SourceKind
    stable_id: str
    display_name: str
    availability: Availability
    locations: tuple[SourceLocation, ...]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SourceSessionRecord:
    record_id: str
    source_id: str
    session_id: str
    locator: str
    label: str | None
    created_at: str | None
    availability: Availability
    last_seen_at: str
