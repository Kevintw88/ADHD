import os
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent))

from idsec import services  # noqa: E402
from idsec.config import PROJECT_ROOT, load_settings  # noqa: E402
from idsec.mockgen import generate  # noqa: E402


@pytest.fixture(scope="session")
def env(tmp_path_factory):
    """在暫存目錄產生模擬資料與設定檔，避免污染專案的 output/。"""
    root = tmp_path_factory.mktemp("idsec")
    generate(root / "mock_data")
    cfg = yaml.safe_load((PROJECT_ROOT / "config" / "settings.yaml").read_text(encoding="utf-8"))
    cfg["output_dir"] = str(root / "output")
    cfg["audit_log"] = str(root / "output" / "audit" / "audit.jsonl")
    cfg["capability_matrix"] = str(PROJECT_ROOT / "config" / "capability_matrix.yaml")
    for e in cfg["entities"]:
        e["data_dir"] = str(root / "mock_data" / e["id"])
        e["reports_dir"] = str(root / "mock_data" / e["id"] / "reports")
    path = root / "settings.yaml"
    path.write_text(yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")
    os.environ["IDSEC_CONFIG"] = str(path)
    services.clear_caches()
    yield load_settings(path)
    services.clear_caches()
