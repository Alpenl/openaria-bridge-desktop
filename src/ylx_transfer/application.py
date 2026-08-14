from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .database import Database, SourceRepository
from .discovery import DeviceDiscovery, JsonHttpDeviceProbe, MediaDiscovery
from .imports import ImportRepository, ImportService, LanImportRepository
from .lan import ConfiguredLanDeviceProbe, LanConnectionSpec, LanDeviceClient, TlsPin
from .publications import (
    EnvironmentS3StoreFactory,
    PublicationRepository,
    PublicationService,
    PublicationSpec,
)
from .runtime import CancellationToken
from .sdk import (
    PipelineSdkClient,
    SdkClient,
    SdkGateway,
    SdkUnavailableError,
    SdkVersionError,
    UnavailableSdkClient,
)
from .tasks import TaskKind, TaskRecord, TaskRepository, TaskState
from .transfers import (
    HttpTransport,
    RemoteTransport,
    TransferDirection,
    TransferRepository,
    TransferScheduler,
    TransferService,
    TransferSpec,
)


class TaskCoordinator:
    def __init__(
        self,
        tasks: TaskRepository,
        imports: ImportService,
        transfers: TransferService,
        publications: PublicationService,
        *,
        import_workers: int = 1,
        transfer_workers: int = 2,
    ) -> None:
        self._tasks = tasks
        self._imports = imports
        self._publications = publications
        self._import_executor = ThreadPoolExecutor(
            max_workers=import_workers,
            thread_name_prefix="ylx-transfer-import",
        )
        self._transfer_scheduler = TransferScheduler(
            transfers, max_workers=transfer_workers
        )
        self._import_tokens: dict[str, CancellationToken] = {}
        self._futures: dict[str, Future[Any]] = {}
        self._lock = threading.Lock()

    def start(self, task_id: str) -> None:
        task = self._tasks.get(task_id)
        if task.state is not TaskState.QUEUED:
            return
        with self._lock:
            active = self._futures.get(task_id)
            if active is not None and not active.done():
                return
            if task.kind is TaskKind.IMPORT:
                token = CancellationToken()
                self._import_tokens[task_id] = token
                future = self._import_executor.submit(self._imports.run, task_id, token)
            elif task.kind is TaskKind.PUBLISH:
                token = CancellationToken()
                self._import_tokens[task_id] = token
                future = self._import_executor.submit(
                    self._publications.run, task_id, token
                )
            elif task.kind in {TaskKind.DOWNLOAD, TaskKind.UPLOAD}:
                future = self._transfer_scheduler.submit(task_id)
            else:
                raise ValueError(f"不支持的任务类型：{task.kind.value}")
            self._futures[task_id] = future
        future.add_done_callback(lambda _: self._forget(task_id))

    def start_queued(self) -> None:
        for task in self._tasks.list():
            if task.state is TaskState.QUEUED:
                self.start(task.task_id)

    def cancel(self, task_id: str) -> TaskRecord:
        task = self._tasks.get(task_id)
        if task.kind in {TaskKind.DOWNLOAD, TaskKind.UPLOAD}:
            self._transfer_scheduler.cancel(task_id)
        else:
            self._tasks.request_cancel(task_id)
            with self._lock:
                token = self._import_tokens.get(task_id)
            if token is not None:
                token.cancel()
        return self._tasks.get(task_id)

    def pause(self, task_id: str) -> TaskRecord:
        task = self._tasks.get(task_id)
        if task.kind not in {TaskKind.DOWNLOAD, TaskKind.UPLOAD}:
            raise ValueError("导入任务不支持暂停，可以取消后重试")
        self._transfer_scheduler.pause(task_id)
        return self._tasks.get(task_id)

    def resume(self, task_id: str) -> TaskRecord:
        task = self._tasks.resume(task_id)
        self.start(task.task_id)
        return self._tasks.get(task_id)

    def retry(self, task_id: str) -> TaskRecord:
        task = self._tasks.retry(task_id)
        self.start(task.task_id)
        return self._tasks.get(task_id)

    def close(self) -> None:
        self._import_executor.shutdown(wait=True)
        self._transfer_scheduler.close()

    def _forget(self, task_id: str) -> None:
        with self._lock:
            self._futures.pop(task_id, None)
            self._import_tokens.pop(task_id, None)


class Application:
    def __init__(
        self,
        data_dir: Path,
        *,
        media_roots: tuple[Path, ...],
        sdk_client: SdkClient | None = None,
        transport: RemoteTransport | None = None,
        publication_store_factory=None,
        import_free_space: Callable[[Path], int] | None = None,
        auto_start: bool = True,
    ) -> None:
        self.data_dir = data_dir.resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.repository_root = self.data_dir / "repository"
        self.database = Database(self.data_dir / "state.db")
        self.database.initialize()
        self.sources = SourceRepository(self.database)
        self.tasks = TaskRepository(self.database)
        self.imports = ImportRepository(self.database)
        self.lan_imports = LanImportRepository(self.database)
        self.transfers = TransferRepository(self.database)
        self.publications = PublicationRepository(self.database)

        self.sdk_error: str | None = None
        if sdk_client is None:
            try:
                sdk_client = PipelineSdkClient()
            except (SdkUnavailableError, SdkVersionError) as exc:
                self.sdk_error = str(exc)
                sdk_client = UnavailableSdkClient()
        self.sdk = SdkGateway(sdk_client)
        self.device_discovery = DeviceDiscovery(self.sources, JsonHttpDeviceProbe())
        self.media_discovery = MediaDiscovery(self.sources, self.sdk, media_roots)
        self.import_service = ImportService(
            repository_root=self.repository_root,
            sources=self.sources,
            tasks=self.tasks,
            imports=self.imports,
            lan_imports=self.lan_imports,
            sdk=self.sdk,
            free_space=import_free_space,
        )
        self.transfer_service = TransferService(
            root=self.repository_root,
            tasks=self.tasks,
            transfers=self.transfers,
            transport=transport or HttpTransport(),
        )
        self.publication_service = PublicationService(
            tasks=self.tasks,
            imports=self.imports,
            publications=self.publications,
            store_factory=publication_store_factory or EnvironmentS3StoreFactory(),
            normalization_root=self.repository_root / ".publication-work",
        )
        self.tasks.recover_incomplete()
        self.coordinator = TaskCoordinator(
            self.tasks,
            self.import_service,
            self.transfer_service,
            self.publication_service,
        )
        if auto_start:
            self.coordinator.start_queued()

    def close(self) -> None:
        self.coordinator.close()

    def health(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "sdk": "ready" if self.sdk_error is None else "unavailable",
            "sdk_error": self.sdk_error,
        }

    def snapshot(self) -> dict[str, Any]:
        sources = self.sources.list_sources()
        sessions = self.sources.list_sessions()
        local_sessions = self.imports.list_local()
        tasks = self.tasks.list()
        publications = self.publications.list()
        return {
            "sources": [
                {
                    "source_id": source.source_id,
                    "kind": source.kind.value,
                    "stable_id": source.stable_id,
                    "display_name": source.display_name,
                    "availability": source.availability.value,
                    "locations": [
                        {
                            "location": location.location,
                            "availability": location.availability.value,
                            "last_seen_at": location.last_seen_at,
                        }
                        for location in source.locations
                    ],
                    "metadata": source.metadata,
                }
                for source in sources
            ],
            "sessions": [
                {
                    "record_id": session.record_id,
                    "source_id": session.source_id,
                    "session_id": session.session_id,
                    "locator": session.locator,
                    "label": session.label,
                    "created_at": session.created_at,
                    "availability": session.availability.value,
                    "last_seen_at": session.last_seen_at,
                }
                for session in sessions
            ],
            "local_sessions": [
                {
                    "local_session_id": session.local_session_id,
                    "session_id": session.session_id,
                    "revision": session.revision,
                    "path": str(session.path),
                    "source_session_record_id": session.source_session_record_id,
                    "total_bytes": session.total_bytes,
                    "imported_at": session.imported_at,
                }
                for session in local_sessions
            ],
            "tasks": [_task_json(task) for task in tasks],
            "publications": [
                {
                    "task_id": item.task_id,
                    "local_session_id": item.spec.local_session_id,
                    "publication_id": item.publication_id,
                    "published_at": item.published_at,
                    "publication_key": item.publication_key,
                    "receipt": item.receipt,
                }
                for item in publications
            ],
        }

    def connect_device(self, value: str | dict[str, Any]) -> dict[str, Any]:
        if isinstance(value, str):
            discovery = self.device_discovery
            endpoint = value
        elif isinstance(value, dict):
            raw_pin = value.get("tls_pin")
            pin = TlsPin(**raw_pin) if isinstance(raw_pin, dict) else None
            spec = LanConnectionSpec(
                endpoint=str(value["endpoint"]),
                credential_ref=(
                    str(value["credential_ref"])
                    if value.get("credential_ref")
                    else None
                ),
                tls_pin=pin,
            )
            client = LanDeviceClient(spec)
            discovery = DeviceDiscovery(self.sources, ConfiguredLanDeviceProbe(client))
            endpoint = client.spec.endpoint
        else:
            raise TypeError("设备连接配置必须是 endpoint 字符串或 JSON 对象")
        source, sessions = discovery.connect(endpoint, CancellationToken())
        return {"source_id": source.source_id, "sessions": len(sessions)}

    def scan_media(self, path: str) -> dict[str, Any]:
        source, sessions = self.media_discovery.scan(Path(path), CancellationToken())
        return {"source_id": source.source_id, "sessions": len(sessions)}

    def enqueue_import(self, record_id: str) -> dict[str, Any]:
        task, created = self.import_service.enqueue(record_id)
        self.coordinator.start(task.task_id)
        return {"task": _task_json(self.tasks.get(task.task_id)), "created": created}

    def enqueue_transfer(self, payload: dict[str, Any]) -> dict[str, Any]:
        local_path = Path(str(payload["local_path"])).expanduser()
        if not local_path.is_absolute():
            local_path = self.repository_root / local_path
        spec = TransferSpec(
            direction=TransferDirection(str(payload["direction"])),
            endpoint=str(payload["endpoint"]),
            local_path=str(local_path),
            expected_sha256=str(payload["expected_sha256"]),
            total_size=int(payload["total_size"]),
            chunk_size=int(payload.get("chunk_size", 4 * 1024 * 1024)),
            credential_ref=(
                str(payload["credential_ref"])
                if payload.get("credential_ref")
                else None
            ),
            publish_url=(
                str(payload["publish_url"]) if payload.get("publish_url") else None
            ),
        )
        task, created = self.transfer_service.enqueue(spec)
        self.coordinator.start(task.task_id)
        return {"task": _task_json(self.tasks.get(task.task_id)), "created": created}

    def enqueue_publication(self, payload: dict[str, Any]) -> dict[str, Any]:
        tls_verify: bool | str = payload.get("tls_verify", True)
        if not isinstance(tls_verify, (bool, str)):
            raise TypeError("tls_verify 必须是布尔值或 CA bundle 路径")
        spec = PublicationSpec(
            local_session_id=str(payload["local_session_id"]),
            bucket=str(payload["bucket"]),
            raw_prefix=str(payload["raw_prefix"]),
            endpoint_url=(
                str(payload["endpoint_url"]) if payload.get("endpoint_url") else None
            ),
            region_name=(
                str(payload["region_name"]) if payload.get("region_name") else None
            ),
            credential_ref=(
                str(payload["credential_ref"])
                if payload.get("credential_ref")
                else None
            ),
            tls_verify=tls_verify,
        )
        task, created = self.publication_service.enqueue(spec)
        self.coordinator.start(task.task_id)
        return {"task": _task_json(self.tasks.get(task.task_id)), "created": created}

    def task_action(self, task_id: str, action: str) -> dict[str, Any]:
        actions = {
            "cancel": self.coordinator.cancel,
            "pause": self.coordinator.pause,
            "resume": self.coordinator.resume,
            "retry": self.coordinator.retry,
        }
        if action not in actions:
            raise ValueError(f"不支持的任务操作：{action}")
        task = actions[action](task_id)
        return {"task": _task_json(task)}


def _task_json(task: TaskRecord) -> dict[str, Any]:
    return {
        "task_id": task.task_id,
        "kind": task.kind.value,
        "state": task.state.value,
        "generation": task.generation,
        "progress": {
            "current": task.progress_current,
            "total": task.progress_total,
            "unit": task.progress_unit,
        },
        "error": (
            {
                "code": task.error_code,
                "message": task.error_message,
                "recovery_action": task.recovery_action,
            }
            if task.error_code is not None
            else None
        ),
        "created_at": task.created_at,
        "updated_at": task.updated_at,
        "finished_at": task.finished_at,
    }
