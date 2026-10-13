"""Hash-chain 稽核日誌。

每筆紀錄含前一筆的雜湊，任何竄改、刪除或插入都會讓 verify() 失敗。
寫入使用檔案鎖，避免多個 MCP Server 同時寫入時交錯。
"""

from __future__ import annotations

import fcntl
import hashlib
import json
from pathlib import Path
from typing import Any

from .models import utcnow

GENESIS = "0" * 64


def _digest(prev_hash: str, body: dict[str, Any]) -> str:
    canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self, fh) -> str:
        fh.seek(0)
        last = GENESIS
        for line in fh:
            line = line.strip()
            if line:
                last = json.loads(line)["hash"]
        return last

    def append(self, actor: str, event: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        with open(self.path, "a+", encoding="utf-8") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                prev = self._last_hash(fh)
                body = {"ts": utcnow(), "actor": actor, "event": event, "data": data or {}, "prev_hash": prev}
                record = {**body, "hash": _digest(prev, body)}
                fh.seek(0, 2)
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
                fh.flush()
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)
        return record

    def verify(self) -> tuple[bool, str]:
        if not self.path.exists():
            return True, "稽核日誌尚未建立"
        prev = GENESIS
        count = 0
        with open(self.path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                rec = json.loads(line)
                stored = rec.pop("hash")
                if rec.get("prev_hash") != prev:
                    return False, f"第 {lineno} 筆的 prev_hash 與前一筆不符（可能被刪除或插入）"
                if _digest(prev, rec) != stored:
                    return False, f"第 {lineno} 筆內容與雜湊不符（可能被竄改）"
                prev = stored
                count += 1
        return True, f"驗證通過，共 {count} 筆"
