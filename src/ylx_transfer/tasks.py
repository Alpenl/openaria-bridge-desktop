from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .database import Database, utc_now


class TaskKind(StrEnum):
    IMPORT = "import"
    DOWNLOAD = "download"
    UPLOAD = "upload"
    PUBLISH = "publish"


class TaskState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSE_REQUESTED = "pause_requested"
    PAUSED = "paused"
    CANCEL_REQUESTED = "cancel_requested"
    CANCELLED = "cancelled"
    FAILED = "failed"
    SUCCEEDED = "succeeded"


TERMINAL_STATES = frozenset(
    {TaskState.CANCELLED, TaskState.FAILED, TaskState.SUCCEEDED}
)


class StaleTaskUpdate(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TaskRecord:
    task_id: str
    kind: TaskKind
    state: TaskState
    generation: int
    idempotency_key: str
    parameters: dict[str, Any]
    progress_current: int
    progress_total: int
    progress_unit: str
    error_code: str | None
    error_message: str | None
    recovery_action: str | None
    created_at: str
    updated_at: str
    started_at: str | None
    finished_at: str | None


class TaskRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    def create(
        self,
        *,
        kind: TaskKind,
        idempotency_key: str,
        parameters: dict[str, Any],
        progress_total: int = 0,
        progress_unit: str = "items",
    ) -> tuple[TaskRecord, bool]:
        if progress_total < 0:
            raise ValueError("progress_total 不能为负数")
        now = utc_now()
        task_id = str(uuid.uuid4())
        try:
            with self._database.connect() as connection:
                connection.execute(
                    """
                    INSERT INTO tasks (
                        task_id, kind, state, generation, idempotency_key,
                        parameters_json, progress_total, progress_unit,
                        created_at, updated_at
                    ) VALUES (?, ?, 'queued', 1, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        task_id,
                        kind.value,
                        idempotency_key,
                        json.dumps(parameters, ensure_ascii=False, sort_keys=True),
                        progress_total,
                        progress_unit,
                        now,
                        now,
                    ),
                )
                self._append_event(
                    connection, task_id, 1, "created", {"state": "queued"}, now
                )
            return self.get(task_id), True
        except sqlite3.IntegrityError:
            with self._database.connect() as connection:
                row = connection.execute(
                    "SELECT task_id FROM tasks WHERE idempotency_key = ?",
                    (idempotency_key,),
                ).fetchone()
            if row is None:
                raise
            return self.get(row["task_id"]), False

    def get(self, task_id: str) -> TaskRecord:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
        if row is None:
            raise KeyError(task_id)
        return self._from_row(row)

    def list(self) -> tuple[TaskRecord, ...]:
        with self._database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM tasks ORDER BY created_at DESC, task_id"
            ).fetchall()
        return tuple(self._from_row(row) for row in rows)

    def claim(self, task_id: str, generation: int) -> TaskRecord:
        now = utc_now()
        with self._database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE tasks
                SET state = 'running', started_at = COALESCE(started_at, ?),
                    updated_at = ?
                WHERE task_id = ? AND generation = ? AND state = 'queued'
                """,
                (now, now, task_id, generation),
            )
            if cursor.rowcount != 1:
                raise StaleTaskUpdate(f"任务 {task_id} 已被其他执行者处理")
            self._append_event(
                connection, task_id, generation, "state", {"state": "running"}, now
            )
        return self.get(task_id)

    def set_progress(
        self,
        task_id: str,
        generation: int,
        current: int,
        total: int | None = None,
        unit: str | None = None,
    ) -> TaskRecord:
        if current < 0 or (total is not None and total < current):
            raise ValueError("任务进度不合法")
        now = utc_now()
        assignments = ["progress_current = ?", "updated_at = ?"]
        parameters: list[Any] = [current, now]
        if total is not None:
            assignments.append("progress_total = ?")
            parameters.append(total)
        if unit is not None:
            assignments.append("progress_unit = ?")
            parameters.append(unit)
        parameters.extend([task_id, generation])
        with self._database.connect() as connection:
            cursor = connection.execute(
                f"""
                UPDATE tasks SET {", ".join(assignments)}
                WHERE task_id = ? AND generation = ?
                    AND state IN ('running', 'pause_requested', 'cancel_requested')
                """,
                parameters,
            )
            if cursor.rowcount != 1:
                raise StaleTaskUpdate(f"任务 {task_id} 的进度事件已过期")
        return self.get(task_id)

    def succeed(self, task_id: str, generation: int) -> TaskRecord:
        return self._finish(task_id, generation, TaskState.SUCCEEDED)

    def fail(
        self,
        task_id: str,
        generation: int,
        *,
        code: str,
        message: str,
        recovery_action: str,
    ) -> TaskRecord:
        return self._finish(
            task_id,
            generation,
            TaskState.FAILED,
            code=code,
            message=message,
            recovery_action=recovery_action,
        )

    def cancel(self, task_id: str, generation: int) -> TaskRecord:
        return self._finish(task_id, generation, TaskState.CANCELLED)

    def pause(self, task_id: str, generation: int) -> TaskRecord:
        now = utc_now()
        with self._database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE tasks SET state = 'paused', updated_at = ?
                WHERE task_id = ? AND generation = ?
                    AND state IN ('running', 'pause_requested')
                """,
                (now, task_id, generation),
            )
            if cursor.rowcount != 1:
                raise StaleTaskUpdate(f"任务 {task_id} 的暂停事件已过期")
            self._append_event(
                connection,
                task_id,
                generation,
                "state",
                {"state": TaskState.PAUSED.value},
                now,
            )
        return self.get(task_id)

    def request_pause(self, task_id: str) -> TaskRecord:
        task = self.get(task_id)
        if task.state in TERMINAL_STATES or task.state is TaskState.PAUSED:
            return task
        if task.state not in {TaskState.QUEUED, TaskState.RUNNING}:
            raise ValueError("当前任务状态不能暂停")
        now = utc_now()
        target = (
            TaskState.PAUSE_REQUESTED
            if task.state is TaskState.RUNNING
            else TaskState.PAUSED
        )
        with self._database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE tasks SET state = ?, updated_at = ?
                WHERE task_id = ? AND generation = ? AND state = ?
                """,
                (
                    target.value,
                    now,
                    task_id,
                    task.generation,
                    task.state.value,
                ),
            )
            if cursor.rowcount != 1:
                raise StaleTaskUpdate(f"任务 {task_id} 状态已经变化")
            self._append_event(
                connection,
                task_id,
                task.generation,
                "state",
                {"state": target.value},
                now,
            )
        return self.get(task_id)

    def resume(self, task_id: str) -> TaskRecord:
        task = self.get(task_id)
        if task.state is not TaskState.PAUSED:
            raise ValueError("只有已暂停任务可以恢复")
        now = utc_now()
        new_generation = task.generation + 1
        with self._database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE tasks SET state = 'queued', generation = ?, updated_at = ?
                WHERE task_id = ? AND generation = ? AND state = 'paused'
                """,
                (new_generation, now, task_id, task.generation),
            )
            if cursor.rowcount != 1:
                raise StaleTaskUpdate(f"任务 {task_id} 已被其他执行者恢复")
            self._advance_transfer_generation(
                connection, task_id, task.generation, new_generation, now
            )
            self._append_event(
                connection,
                task_id,
                new_generation,
                "resumed",
                {"previous_generation": task.generation},
                now,
            )
        return self.get(task_id)

    def request_cancel(self, task_id: str) -> TaskRecord:
        task = self.get(task_id)
        if task.state in TERMINAL_STATES:
            return task
        now = utc_now()
        target = (
            TaskState.CANCEL_REQUESTED
            if task.state in {TaskState.RUNNING, TaskState.PAUSE_REQUESTED}
            else TaskState.CANCELLED
        )
        finished_at = now if target is TaskState.CANCELLED else None
        with self._database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE tasks SET state = ?, updated_at = ?, finished_at = ?
                WHERE task_id = ? AND generation = ? AND state = ?
                """,
                (
                    target.value,
                    now,
                    finished_at,
                    task_id,
                    task.generation,
                    task.state.value,
                ),
            )
            if cursor.rowcount != 1:
                raise StaleTaskUpdate(f"任务 {task_id} 状态已经变化")
            self._append_event(
                connection,
                task_id,
                task.generation,
                "state",
                {"state": target.value},
                now,
            )
        return self.get(task_id)

    def retry(self, task_id: str) -> TaskRecord:
        task = self.get(task_id)
        if task.state not in {TaskState.FAILED, TaskState.CANCELLED}:
            raise ValueError("只有失败或取消的任务可以重试")
        now = utc_now()
        new_generation = task.generation + 1
        with self._database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE tasks
                SET state = 'queued', generation = ?, error_code = NULL,
                    error_message = NULL, recovery_action = NULL,
                    finished_at = NULL, updated_at = ?
                WHERE task_id = ? AND generation = ? AND state = ?
                """,
                (
                    new_generation,
                    now,
                    task_id,
                    task.generation,
                    task.state.value,
                ),
            )
            if cursor.rowcount != 1:
                raise StaleTaskUpdate(f"任务 {task_id} 已被其他执行者重试")
            self._advance_transfer_generation(
                connection, task_id, task.generation, new_generation, now
            )
            self._append_event(
                connection,
                task_id,
                new_generation,
                "retried",
                {"previous_generation": task.generation},
                now,
            )
        return self.get(task_id)

    def recover_incomplete(self) -> tuple[TaskRecord, ...]:
        now = utc_now()
        recovered_ids: list[str] = []
        with self._database.connect() as connection:
            rows = connection.execute(
                """
                SELECT task_id, generation, state FROM tasks
                WHERE state IN ('running', 'pause_requested', 'cancel_requested')
                """
            ).fetchall()
            for row in rows:
                new_generation = row["generation"] + 1
                target_state = (
                    TaskState.CANCELLED
                    if row["state"] == TaskState.CANCEL_REQUESTED.value
                    else (
                        TaskState.PAUSED
                        if row["state"] == TaskState.PAUSE_REQUESTED.value
                        else TaskState.QUEUED
                    )
                )
                finished_at = now if target_state is TaskState.CANCELLED else None
                cursor = connection.execute(
                    """
                    UPDATE tasks SET state = ?, generation = ?, updated_at = ?,
                        finished_at = ?
                    WHERE task_id = ? AND generation = ? AND state = ?
                    """,
                    (
                        target_state.value,
                        new_generation,
                        now,
                        finished_at,
                        row["task_id"],
                        row["generation"],
                        row["state"],
                    ),
                )
                if cursor.rowcount != 1:
                    raise StaleTaskUpdate(f"任务 {row['task_id']} 已被其他恢复操作处理")
                self._advance_transfer_generation(
                    connection,
                    row["task_id"],
                    row["generation"],
                    new_generation,
                    now,
                )
                self._append_event(
                    connection,
                    row["task_id"],
                    new_generation,
                    "recovered",
                    {
                        "previous_generation": row["generation"],
                        "state": target_state.value,
                    },
                    now,
                )
                recovered_ids.append(row["task_id"])
        return tuple(self.get(task_id) for task_id in recovered_ids)

    @staticmethod
    def _advance_transfer_generation(
        connection,
        task_id: str,
        previous_generation: int,
        new_generation: int,
        now: str,
    ) -> None:
        cursor = connection.execute(
            """
            UPDATE transfer_operations
            SET checkpoint_generation = ?, updated_at = ?
            WHERE task_id = ? AND checkpoint_generation = ?
            """,
            (new_generation, now, task_id, previous_generation),
        )
        if cursor.rowcount == 0:
            operation = connection.execute(
                "SELECT 1 FROM transfer_operations WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            if operation is not None:
                raise StaleTaskUpdate(f"传输任务 {task_id} 的执行代次与任务账本不一致")
        cursor = connection.execute(
            """
            UPDATE lan_import_operations
            SET checkpoint_generation = ?, updated_at = ?
            WHERE task_id = ? AND checkpoint_generation = ?
            """,
            (new_generation, now, task_id, previous_generation),
        )
        if cursor.rowcount == 0:
            operation = connection.execute(
                "SELECT 1 FROM lan_import_operations WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            if operation is not None:
                raise StaleTaskUpdate(
                    f"LAN 导入任务 {task_id} 的执行代次与任务账本不一致"
                )
        cursor = connection.execute(
            """
            UPDATE publication_operations
            SET checkpoint_generation = ?, updated_at = ?
            WHERE task_id = ? AND checkpoint_generation = ?
            """,
            (new_generation, now, task_id, previous_generation),
        )
        if cursor.rowcount == 0:
            operation = connection.execute(
                "SELECT 1 FROM publication_operations WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            if operation is not None:
                raise StaleTaskUpdate(f"发布任务 {task_id} 的执行代次与任务账本不一致")

    def _finish(
        self,
        task_id: str,
        generation: int,
        state: TaskState,
        *,
        code: str | None = None,
        message: str | None = None,
        recovery_action: str | None = None,
    ) -> TaskRecord:
        now = utc_now()
        with self._database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE tasks
                SET state = ?, error_code = ?, error_message = ?,
                    recovery_action = ?, updated_at = ?, finished_at = ?
                WHERE task_id = ? AND generation = ?
                    AND state IN ('running', 'pause_requested', 'cancel_requested')
                """,
                (
                    state.value,
                    code,
                    message,
                    recovery_action,
                    now,
                    now,
                    task_id,
                    generation,
                ),
            )
            if cursor.rowcount != 1:
                raise StaleTaskUpdate(f"任务 {task_id} 的完成事件已过期")
            self._append_event(
                connection,
                task_id,
                generation,
                "state",
                {"state": state.value, "error_code": code},
                now,
            )
        return self.get(task_id)

    @staticmethod
    def _append_event(
        connection,
        task_id: str,
        generation: int,
        event_type: str,
        payload: dict[str, Any],
        created_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO task_events (
                task_id, generation, event_type, payload_json, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                task_id,
                generation,
                event_type,
                json.dumps(payload, ensure_ascii=False, sort_keys=True),
                created_at,
            ),
        )

    @staticmethod
    def _from_row(row) -> TaskRecord:
        return TaskRecord(
            task_id=row["task_id"],
            kind=TaskKind(row["kind"]),
            state=TaskState(row["state"]),
            generation=row["generation"],
            idempotency_key=row["idempotency_key"],
            parameters=json.loads(row["parameters_json"]),
            progress_current=row["progress_current"],
            progress_total=row["progress_total"],
            progress_unit=row["progress_unit"],
            error_code=row["error_code"],
            error_message=row["error_message"],
            recovery_action=row["recovery_action"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
        )
