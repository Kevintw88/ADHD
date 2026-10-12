"""模擬後端：從 data_dir 讀取正規化 JSON 快照（由 idsec mock-gen 產生）。"""

from __future__ import annotations

import json
from functools import cached_property
from pathlib import Path

from ..config import EntityConfig
from ..models import ADSnapshot, EntraSnapshot, IdentityGraph, Tooling


class MockBackend:
    def __init__(self, entity: EntityConfig):
        self.entity = entity
        d = entity.path(entity.data_dir)
        if d is None or not d.exists():
            raise FileNotFoundError(f"找不到模擬資料目錄：{d}（先執行 idsec mock-gen）")
        self.dir: Path = d

    def _load(self, name: str) -> dict:
        return json.loads((self.dir / name).read_text(encoding="utf-8"))

    @cached_property
    def _ad(self) -> ADSnapshot:
        return ADSnapshot.model_validate(self._load("ad.json"))

    @cached_property
    def _entra(self) -> EntraSnapshot:
        return EntraSnapshot.model_validate(self._load("entra.json"))

    def ad_snapshot(self) -> ADSnapshot:
        return self._ad

    def entra_snapshot(self) -> EntraSnapshot:
        return self._entra

    def tooling(self) -> Tooling:
        return Tooling.model_validate(self._load("tooling.json"))

    def identity_graph(self) -> IdentityGraph:
        return IdentityGraph.model_validate(self._load("graph.json"))
