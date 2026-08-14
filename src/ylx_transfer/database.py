from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import (
    Availability,
    SourceKind,
    SourceLocation,
    SourceRecord,
    SourceSessionRecord,
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


class StaleSourceObservation(RuntimeError):
    pass


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS sources (
                    source_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL CHECK (kind IN ('device', 'media')),
                    stable_id TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    availability TEXT NOT NULL CHECK (availability IN ('online', 'offline')),
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE (kind, stable_id)
                );

                CREATE TABLE IF NOT EXISTS source_locations (
                    source_id TEXT NOT NULL REFERENCES sources(source_id) ON DELETE CASCADE,
                    location TEXT NOT NULL,
                    availability TEXT NOT NULL CHECK (availability IN ('online', 'offline')),
                    last_seen_at TEXT NOT NULL,
                    PRIMARY KEY (source_id, location)
                );

                CREATE TABLE IF NOT EXISTS source_sessions (
                    record_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL REFERENCES sources(source_id) ON DELETE CASCADE,
                    session_id TEXT NOT NULL,
                    locator TEXT NOT NULL,
                    label TEXT,
                    created_at TEXT,
                    availability TEXT NOT NULL CHECK (availability IN ('online', 'offline')),
                    last_seen_at TEXT NOT NULL,
                    UNIQUE (source_id, session_id)
                );

                CREATE INDEX IF NOT EXISTS idx_source_sessions_source
                    ON source_sessions(source_id, availability);

                CREATE TABLE IF NOT EXISTS source_observations (
                    kind TEXT NOT NULL CHECK (kind IN ('device', 'media')),
                    location TEXT NOT NULL,
                    issued_token INTEGER NOT NULL DEFAULT 0 CHECK (issued_token >= 0),
                    applied_token INTEGER NOT NULL DEFAULT 0 CHECK (applied_token >= 0),
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (kind, location)
                );

                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    state TEXT NOT NULL,
                    generation INTEGER NOT NULL CHECK (generation > 0),
                    idempotency_key TEXT NOT NULL UNIQUE,
                    parameters_json TEXT NOT NULL,
                    progress_current INTEGER NOT NULL DEFAULT 0 CHECK (progress_current >= 0),
                    progress_total INTEGER NOT NULL DEFAULT 0 CHECK (progress_total >= 0),
                    progress_unit TEXT NOT NULL DEFAULT 'items',
                    error_code TEXT,
                    error_message TEXT,
                    recovery_action TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_tasks_state
                    ON tasks(state, created_at);

                CREATE TABLE IF NOT EXISTS task_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
                    generation INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS import_operations (
                    task_id TEXT PRIMARY KEY REFERENCES tasks(task_id) ON DELETE CASCADE,
                    source_session_record_id TEXT NOT NULL
                        REFERENCES source_sessions(record_id),
                    session_id TEXT NOT NULL,
                    revision TEXT NOT NULL,
                    staging_path TEXT NOT NULL,
                    final_path TEXT NOT NULL,
                    copy_plan_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS local_sessions (
                    local_session_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    revision TEXT NOT NULL,
                    path TEXT NOT NULL UNIQUE,
                    source_session_record_id TEXT NOT NULL
                        REFERENCES source_sessions(record_id),
                    total_bytes INTEGER NOT NULL CHECK (total_bytes >= 0),
                    imported_at TEXT NOT NULL,
                    UNIQUE (session_id, revision)
                );

                CREATE TABLE IF NOT EXISTS lan_import_operations (
                    task_id TEXT PRIMARY KEY REFERENCES tasks(task_id) ON DELETE CASCADE,
                    spec_json TEXT NOT NULL,
                    manifest_sha256 TEXT NOT NULL,
                    checkpoint_generation INTEGER NOT NULL CHECK (checkpoint_generation > 0),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS lan_import_checkpoints (
                    task_id TEXT NOT NULL
                        REFERENCES lan_import_operations(task_id) ON DELETE CASCADE,
                    relative_path TEXT NOT NULL,
                    offset_bytes INTEGER NOT NULL DEFAULT 0 CHECK (offset_bytes >= 0),
                    remote_identity TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (task_id, relative_path)
                );

                CREATE TABLE IF NOT EXISTS transfer_operations (
                    task_id TEXT PRIMARY KEY REFERENCES tasks(task_id) ON DELETE CASCADE,
                    direction TEXT NOT NULL CHECK (direction IN ('download', 'upload')),
                    spec_json TEXT NOT NULL,
                    offset_bytes INTEGER NOT NULL DEFAULT 0 CHECK (offset_bytes >= 0),
                    remote_identity TEXT,
                    checkpoint_generation INTEGER NOT NULL CHECK (checkpoint_generation > 0),
                    completion_json TEXT,
                    receipt_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS publication_operations (
                    task_id TEXT PRIMARY KEY REFERENCES tasks(task_id) ON DELETE CASCADE,
                    local_session_id TEXT NOT NULL
                        REFERENCES local_sessions(local_session_id),
                    spec_json TEXT NOT NULL,
                    publication_id TEXT NOT NULL,
                    published_at TEXT NOT NULL,
                    publication_key TEXT,
                    checkpoint_generation INTEGER NOT NULL CHECK (checkpoint_generation > 0),
                    receipt_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        try:
            with connection:
                yield connection
        finally:
            connection.close()


class SourceRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    def begin_observation(self, kind: SourceKind, location: str) -> int:
        now = utc_now()
        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT INTO source_observations (
                    kind, location, issued_token, applied_token, updated_at
                ) VALUES (?, ?, 0, 0, ?)
                ON CONFLICT(kind, location) DO NOTHING
                """,
                (kind.value, location, now),
            )
            connection.execute(
                """
                UPDATE source_observations
                SET issued_token = issued_token + 1, updated_at = ?
                WHERE kind = ? AND location = ?
                """,
                (now, kind.value, location),
            )
            row = connection.execute(
                """
                SELECT issued_token FROM source_observations
                WHERE kind = ? AND location = ?
                """,
                (kind.value, location),
            ).fetchone()
        return int(row["issued_token"])

    def apply_observation(
        self,
        *,
        kind: SourceKind,
        location: str,
        token: int,
        stable_id: str,
        display_name: str,
        sessions: Iterable[tuple[str, str, str | None, str | None]],
        metadata: dict[str, Any] | None = None,
        exclusive_location: bool = False,
    ) -> tuple[SourceRecord, tuple[SourceSessionRecord, ...]]:
        now = utc_now()
        encoded_metadata = json.dumps(
            metadata or {}, ensure_ascii=False, sort_keys=True
        )
        observed_sessions = tuple(sessions)
        with self._database.connect() as connection:
            self._accept_observation(connection, kind, location, token, now)
            row = connection.execute(
                "SELECT source_id FROM sources WHERE kind = ? AND stable_id = ?",
                (kind.value, stable_id),
            ).fetchone()
            if row is None:
                source_id = str(uuid.uuid4())
                connection.execute(
                    """
                    INSERT INTO sources (
                        source_id, kind, stable_id, display_name, availability,
                        metadata_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'online', ?, ?, ?)
                    """,
                    (
                        source_id,
                        kind.value,
                        stable_id,
                        display_name,
                        encoded_metadata,
                        now,
                        now,
                    ),
                )
            else:
                source_id = row["source_id"]
                connection.execute(
                    """
                    UPDATE sources
                    SET display_name = ?, availability = 'online',
                        metadata_json = ?, updated_at = ?
                    WHERE source_id = ?
                    """,
                    (display_name, encoded_metadata, now, source_id),
                )

            if exclusive_location:
                connection.execute(
                    """
                    UPDATE source_locations SET availability = 'offline'
                    WHERE source_id = ? AND location <> ?
                    """,
                    (source_id, location),
                )
            connection.execute(
                """
                INSERT INTO source_locations (
                    source_id, location, availability, last_seen_at
                ) VALUES (?, ?, 'online', ?)
                ON CONFLICT(source_id, location) DO UPDATE SET
                    availability = 'online', last_seen_at = excluded.last_seen_at
                """,
                (source_id, location, now),
            )
            self._apply_sessions(connection, source_id, observed_sessions, now)
        return self.get_source(source_id), self.list_sessions(source_id=source_id)

    def mark_observation_offline(
        self, kind: SourceKind, location: str, token: int
    ) -> bool:
        now = utc_now()
        with self._database.connect() as connection:
            try:
                self._accept_observation(connection, kind, location, token, now)
            except StaleSourceObservation:
                return False
            self._mark_location_offline(connection, kind, location, now)
        return True

    def observe_source(
        self,
        *,
        kind: SourceKind,
        stable_id: str,
        display_name: str,
        location: str,
        metadata: dict[str, Any] | None = None,
        exclusive_location: bool = False,
    ) -> SourceRecord:
        now = utc_now()
        encoded_metadata = json.dumps(
            metadata or {}, ensure_ascii=False, sort_keys=True
        )
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT source_id FROM sources WHERE kind = ? AND stable_id = ?",
                (kind.value, stable_id),
            ).fetchone()
            if row is None:
                source_id = str(uuid.uuid4())
                connection.execute(
                    """
                    INSERT INTO sources (
                        source_id, kind, stable_id, display_name, availability,
                        metadata_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'online', ?, ?, ?)
                    """,
                    (
                        source_id,
                        kind.value,
                        stable_id,
                        display_name,
                        encoded_metadata,
                        now,
                        now,
                    ),
                )
            else:
                source_id = row["source_id"]
                connection.execute(
                    """
                    UPDATE sources
                    SET display_name = ?, availability = 'online',
                        metadata_json = ?, updated_at = ?
                    WHERE source_id = ?
                    """,
                    (display_name, encoded_metadata, now, source_id),
                )

            if exclusive_location:
                connection.execute(
                    """
                    UPDATE source_locations SET availability = 'offline'
                    WHERE source_id = ? AND location <> ?
                    """,
                    (source_id, location),
                )
            connection.execute(
                """
                INSERT INTO source_locations (
                    source_id, location, availability, last_seen_at
                ) VALUES (?, ?, 'online', ?)
                ON CONFLICT(source_id, location) DO UPDATE SET
                    availability = 'online', last_seen_at = excluded.last_seen_at
                """,
                (source_id, location, now),
            )
        return self.get_source(source_id)

    def mark_location_offline(self, kind: SourceKind, location: str) -> None:
        now = utc_now()
        with self._database.connect() as connection:
            self._mark_location_offline(connection, kind, location, now)

    def observe_sessions(
        self,
        source_id: str,
        sessions: Iterable[tuple[str, str, str | None, str | None]],
    ) -> tuple[SourceSessionRecord, ...]:
        now = utc_now()
        with self._database.connect() as connection:
            self._apply_sessions(connection, source_id, tuple(sessions), now)
        return self.list_sessions(source_id=source_id)

    @staticmethod
    def _accept_observation(
        connection,
        kind: SourceKind,
        location: str,
        token: int,
        now: str,
    ) -> None:
        cursor = connection.execute(
            """
            UPDATE source_observations
            SET applied_token = ?, updated_at = ?
            WHERE kind = ? AND location = ?
                AND issued_token = ? AND applied_token < ?
            """,
            (token, now, kind.value, location, token, token),
        )
        if cursor.rowcount != 1:
            raise StaleSourceObservation(
                f"{kind.value} 来源 {location} 的观察结果 {token} 已过期"
            )

    @staticmethod
    def _mark_location_offline(
        connection, kind: SourceKind, location: str, now: str
    ) -> None:
        rows = connection.execute(
            """
            SELECT s.source_id
            FROM sources s
            JOIN source_locations l ON l.source_id = s.source_id
            WHERE s.kind = ? AND l.location = ?
            """,
            (kind.value, location),
        ).fetchall()
        for row in rows:
            source_id = row["source_id"]
            connection.execute(
                """
                UPDATE source_locations
                SET availability = 'offline', last_seen_at = ?
                WHERE source_id = ? AND location = ?
                """,
                (now, source_id, location),
            )
            online = connection.execute(
                """
                SELECT 1 FROM source_locations
                WHERE source_id = ? AND availability = 'online' LIMIT 1
                """,
                (source_id,),
            ).fetchone()
            if online is None:
                connection.execute(
                    """
                    UPDATE sources SET availability = 'offline', updated_at = ?
                    WHERE source_id = ?
                    """,
                    (now, source_id),
                )
                connection.execute(
                    """
                    UPDATE source_sessions SET availability = 'offline'
                    WHERE source_id = ?
                    """,
                    (source_id,),
                )

    @staticmethod
    def _apply_sessions(connection, source_id: str, sessions, now: str) -> None:
        observed_ids: list[str] = []
        for session_id, locator, label, created_at in sessions:
            observed_ids.append(session_id)
            row = connection.execute(
                """
                SELECT record_id FROM source_sessions
                WHERE source_id = ? AND session_id = ?
                """,
                (source_id, session_id),
            ).fetchone()
            record_id = row["record_id"] if row else str(uuid.uuid4())
            connection.execute(
                """
                INSERT INTO source_sessions (
                    record_id, source_id, session_id, locator, label,
                    created_at, availability, last_seen_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'online', ?)
                ON CONFLICT(source_id, session_id) DO UPDATE SET
                    locator = excluded.locator,
                    label = excluded.label,
                    created_at = excluded.created_at,
                    availability = 'online',
                    last_seen_at = excluded.last_seen_at
                """,
                (
                    record_id,
                    source_id,
                    session_id,
                    locator,
                    label,
                    created_at,
                    now,
                ),
            )

        if observed_ids:
            placeholders = ",".join("?" for _ in observed_ids)
            connection.execute(
                f"""
                UPDATE source_sessions SET availability = 'offline'
                WHERE source_id = ? AND session_id NOT IN ({placeholders})
                """,
                (source_id, *observed_ids),
            )
        else:
            connection.execute(
                """
                UPDATE source_sessions SET availability = 'offline'
                WHERE source_id = ?
                """,
                (source_id,),
            )

    def get_source(self, source_id: str) -> SourceRecord:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sources WHERE source_id = ?", (source_id,)
            ).fetchone()
            if row is None:
                raise KeyError(source_id)
            locations = connection.execute(
                """
                SELECT location, availability, last_seen_at
                FROM source_locations WHERE source_id = ?
                ORDER BY availability DESC, location
                """,
                (source_id,),
            ).fetchall()
        return self._source_from_rows(row, locations)

    def list_sources(self) -> tuple[SourceRecord, ...]:
        with self._database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM sources ORDER BY display_name, source_id"
            ).fetchall()
            result = []
            for row in rows:
                locations = connection.execute(
                    """
                    SELECT location, availability, last_seen_at
                    FROM source_locations WHERE source_id = ?
                    ORDER BY availability DESC, location
                    """,
                    (row["source_id"],),
                ).fetchall()
                result.append(self._source_from_rows(row, locations))
        return tuple(result)

    def list_sessions(
        self, source_id: str | None = None
    ) -> tuple[SourceSessionRecord, ...]:
        query = "SELECT * FROM source_sessions"
        parameters: tuple[str, ...] = ()
        if source_id is not None:
            query += " WHERE source_id = ?"
            parameters = (source_id,)
        query += " ORDER BY created_at DESC, session_id"
        with self._database.connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return tuple(
            SourceSessionRecord(
                record_id=row["record_id"],
                source_id=row["source_id"],
                session_id=row["session_id"],
                locator=row["locator"],
                label=row["label"],
                created_at=row["created_at"],
                availability=Availability(row["availability"]),
                last_seen_at=row["last_seen_at"],
            )
            for row in rows
        )

    def get_session(self, record_id: str) -> SourceSessionRecord:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM source_sessions WHERE record_id = ?", (record_id,)
            ).fetchone()
        if row is None:
            raise KeyError(record_id)
        return SourceSessionRecord(
            record_id=row["record_id"],
            source_id=row["source_id"],
            session_id=row["session_id"],
            locator=row["locator"],
            label=row["label"],
            created_at=row["created_at"],
            availability=Availability(row["availability"]),
            last_seen_at=row["last_seen_at"],
        )

    @staticmethod
    def _source_from_rows(row: sqlite3.Row, locations) -> SourceRecord:
        return SourceRecord(
            source_id=row["source_id"],
            kind=SourceKind(row["kind"]),
            stable_id=row["stable_id"],
            display_name=row["display_name"],
            availability=Availability(row["availability"]),
            locations=tuple(
                SourceLocation(
                    location=item["location"],
                    availability=Availability(item["availability"]),
                    last_seen_at=item["last_seen_at"],
                )
                for item in locations
            ),
            metadata=json.loads(row["metadata_json"]),
        )
