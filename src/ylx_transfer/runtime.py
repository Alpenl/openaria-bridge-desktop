from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from threading import Event
from typing import Self, TypeVar

T = TypeVar("T")


class OperationCancelled(RuntimeError):
    """后台操作在安全检查点响应了取消请求。"""


@dataclass(slots=True)
class CancellationToken:
    _event: Event = field(default_factory=Event)

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise OperationCancelled("操作已取消")


@dataclass(frozen=True, slots=True)
class BackgroundOperation:
    future: Future[object]
    token: CancellationToken

    def cancel(self) -> None:
        self.token.cancel()


class BackgroundExecutor:
    """只负责进程内调度；任务事实由后续持久存储负责。"""

    def __init__(self, max_workers: int = 2) -> None:
        if max_workers < 1:
            raise ValueError("max_workers 必须大于零")
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="ylx-transfer",
        )

    def submit(
        self, operation: Callable[[CancellationToken], T]
    ) -> BackgroundOperation:
        token = CancellationToken()
        future: Future[object] = self._executor.submit(operation, token)
        return BackgroundOperation(future=future, token=token)

    def close(self) -> None:
        self._executor.shutdown(wait=True, cancel_futures=False)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
