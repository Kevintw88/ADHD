"""後端選擇：依法人設定回傳 mock 或 live 後端，兩者輸出同一套正規化模型。"""

from __future__ import annotations

from typing import Protocol

from ..config import EntityConfig
from ..models import ADSnapshot, EntraSnapshot, IdentityGraph, Tooling


class Backend(Protocol):
    entity: EntityConfig

    def ad_snapshot(self) -> ADSnapshot: ...
    def entra_snapshot(self) -> EntraSnapshot: ...
    def tooling(self) -> Tooling: ...
    def identity_graph(self) -> IdentityGraph: ...


def get_backend(entity: EntityConfig) -> Backend:
    if entity.backend == "mock":
        from .mock import MockBackend

        return MockBackend(entity)
    from .live import LiveBackend

    return LiveBackend(entity)
