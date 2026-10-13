"""設定載入：config/settings.yaml，可用環境變數覆寫。"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

def _project_root() -> Path:
    """IDSEC_HOME > 原始碼目錄（editable 安裝）> 目前目錄（一般安裝，例如容器 WORKDIR）。"""
    if home := os.environ.get("IDSEC_HOME"):
        return Path(home).resolve()
    src_root = Path(__file__).resolve().parents[2]
    return src_root if (src_root / "config" / "settings.yaml").exists() else Path.cwd()


PROJECT_ROOT = _project_root()


class LdapConfig(BaseModel):
    server: str
    base_dn: str
    use_ssl: bool = True
    user_env: str = "IDSEC_LDAP_USER"
    password_env: str = "IDSEC_LDAP_PASSWORD"


class GraphConfig(BaseModel):
    tenant_id: str
    client_id: str
    cert_path: str | None = None
    cert_thumbprint: str | None = None
    secret_env: str = "IDSEC_GRAPH_SECRET"


class Neo4jConfig(BaseModel):
    uri: str
    user: str = "neo4j"
    password_env: str = "IDSEC_NEO4J_PASSWORD"


class EntityConfig(BaseModel):
    id: str
    name: str
    backend: Literal["mock", "live"] = "mock"
    data_dir: str | None = None          # mock：快照目錄
    reports_dir: str | None = None       # PingCastle 等報告檔目錄
    tooling_file: str | None = None      # live：IT 填寫的工具與遙測現況
    ldap: LdapConfig | None = None
    graph: GraphConfig | None = None
    neo4j: Neo4jConfig | None = None

    def path(self, value: str | None) -> Path | None:
        if value is None:
            return None
        p = Path(value)
        return p if p.is_absolute() else PROJECT_ROOT / p


class ModelConfig(BaseModel):
    fast: str = "qwen3.8-flash-next"
    reason: str = "glm-5.3-flash"
    base_url: str = "http://litellm:4000"


class Settings(BaseModel):
    output_dir: str = "output"
    audit_log: str = "output/audit/audit.jsonl"
    capability_matrix: str = "config/capability_matrix.yaml"
    models: ModelConfig = Field(default_factory=ModelConfig)
    entities: list[EntityConfig] = Field(default_factory=list)

    def entity(self, entity_id: str) -> EntityConfig:
        for e in self.entities:
            if e.id == entity_id:
                return e
        known = ", ".join(e.id for e in self.entities)
        raise KeyError(f"找不到法人 {entity_id!r}，設定中有：{known}")

    def resolve(self, value: str) -> Path:
        p = Path(value)
        return p if p.is_absolute() else PROJECT_ROOT / p


def load_settings(path: str | Path | None = None) -> Settings:
    path = Path(path or os.environ.get("IDSEC_CONFIG", PROJECT_ROOT / "config" / "settings.yaml"))
    data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
    settings = Settings.model_validate(data or {})
    if v := os.environ.get("IDSEC_MODEL_FAST"):
        settings.models.fast = v
    if v := os.environ.get("IDSEC_MODEL_REASON"):
        settings.models.reason = v
    if v := os.environ.get("ANTHROPIC_BASE_URL"):
        settings.models.base_url = v
    if v := os.environ.get("IDSEC_OUTPUT_DIR"):
        settings.output_dir = v
    return settings
