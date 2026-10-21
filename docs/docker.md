# Docker 部署（lab）

一個映像包含 lab 端的全部工具：bundle 驗收、分析與攻擊路徑、唯讀 MCP 伺服器、調查 Agent。只用 Python 標準函式庫，映像內沒有 `pip install`，也沒有 shell。

## 建置與帶進隔離環境

lab 若無法連外，在可連外的機器建置後匯出：

```bash
git clone https://github.com/Kevintw88/ADHD.git && cd ADHD
docker build -t adhd:0.4.0 .
docker save adhd:0.4.0 | gzip > adhd-0.4.0.tar.gz
sha256sum adhd-0.4.0.tar.gz > adhd-0.4.0.tar.gz.sha256
```

在 lab 主機：

```bash
sha256sum -c adhd-0.4.0.tar.gz.sha256
docker load < adhd-0.4.0.tar.gz
docker run --rm --network none adhd:0.4.0 selftest     # 在映像內跑完整測試
```

基底映像預設為 `python:3.12-slim`；組織有自己的映像倉庫或核准的基底映像時，用 `--build-arg BASE=<映像>` 指定（需含 Python 3.8 以上）。

## 使用（docker compose）

`compose.yaml` 定義兩個服務，都以非 root（預設 uid 10001）、唯讀根目錄、移除所有 capabilities、`no-new-privileges` 執行：

| 服務 | 網路 | 掛載 | 用途 |
|---|---|---|---|
| `adhd` | **無**（`network_mode: none`） | intake 唯讀、reports 可寫 | 驗收、分析、路徑查詢、MCP 伺服器 |
| `agent` | 可連到模型服務 | 只有 reports（看不到原始 bundle） | 調查 Agent |

```bash
cd ADHD
export ADHD_INTAKE=/srv/adhd/intake ADHD_REPORTS=/srv/adhd/reports
export ADHD_UID=$(id -u) ADHD_GID=$(id -g)      # 讓輸出檔屬於目前使用者

# 驗收與分析（萬用字元請加引號，由容器內展開）
docker compose run --rm adhd verify-bundle '/data/intake/ADHD-Collect-SubA*20261020*.zip'
docker compose run --rm adhd sanity        '/data/intake/ADHD-Collect-SubA*20261020*.zip'
docker compose run --rm adhd analyze       '/data/intake/ADHD-Collect-SubA*20261020*.zip' --out /data/reports/SubA-20261020

# 攻擊路徑查詢
docker compose run --rm adhd paths '/data/intake/ADHD-Collect-SubA*20261020*.zip' --to CA-TWCA-01

# 調查 Agent（模型服務在主機或 lab 內其他主機）
export ADHD_LLM_BASE_URL=http://gpu01:8000/v1 ADHD_LLM_MODEL=<served-model-name>
docker compose run --rm agent agent --report-dir /data/reports/SubA-20261020 --task report
docker compose run --rm agent eval  --report-dir /data/reports/SubA-20261020 --model <A> --model <B> --runs 3
```

模型服務跑在同一台主機時，`ADHD_LLM_BASE_URL` 預設為 `http://host.docker.internal:8000/v1`。

## 讓其他 MCP 用戶端使用

MCP 伺服器走 stdio，用 `docker run -i` 啟動即可，例如在 MCP 用戶端的設定中：

```json
{
  "mcpServers": {
    "adhd": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
               "-v", "/srv/adhd/reports:/data/reports:ro", "adhd:0.4.0", "mcp", "/data/reports/SubA-20261020"]
    }
  }
}
```

## 注意

- 映像只含程式；bundle、報告、金鑰都透過掛載，不會被打包（`.dockerignore` 排除了 bundle、輸出與金鑰檔名）。
- 假名化金鑰與對照表不需要也不應該出現在 lab。
- `adhd` 服務沒有網路，確保分析過程不會把資料送出；只有 `agent` 服務能連線，且只能看到分析輸出。
