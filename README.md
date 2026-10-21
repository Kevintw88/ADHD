# ADHD — AD + Entra ID Hybrid Defense

以 AI（地端模型）協助 AD 與 Entra ID 混合環境的預防評估、攻擊路徑分析、威脅偵測與架構硬化。

目前階段：**MVP（Phase 0 + 1，唯讀）**：收集、離線分析與攻擊路徑、唯讀 MCP 伺服器、地端模型調查 Agent、Docker 部署。先在各公司環境盤點，再依實際環境啟用分析模組（偵測後運行）。

## 架構概念

```
 子公司 / 總公司環境                         Lab（離線）
┌───────────────────────────┐   bundle   ┌──────────────────────────────────────┐
│ collectors/powershell/    │   (.zip)   │ verify_bundle / bundle_sanity  驗收   │
│   Collect-ADHD.ps1        │ ─────────▶ │        ↓                              │
│   唯讀 LDAP / Graph /     │            │ adhd/ 關聯圖 + 規則（tools/analyze.py）│
│   Event Log，預設假名化    │            │        ↓ findings.json / graph.sqlite │
└───────────────────────────┘            │ MCP 伺服器（唯讀）→ 地端模型 Agent     │
                                          └──────────────────────────────────────┘
```

## 目錄

| 路徑 | 說明 |
|---|---|
| `collectors/powershell/` | 現場資料收集器與使用說明（需要準備什麼、怎麼跑、輸出格式） |
| `tools/verify_bundle.py` | Lab 端 bundle 驗收（雜湊、筆數、禁止欄位、假名化外洩檢查），僅用標準函式庫 |
| `tools/bundle_sanity.py` | 驗收後的語意檢查（收集是否悄悄不完整、跨 bundle 假名一致性） |
| `adhd/`、`tools/analyze.py` | 離線分析：AD / Entra 混合關聯圖、66 條規則與攻擊路徑，輸出報告、JSON 與 SQLite（[docs/analysis.md](docs/analysis.md)、[規則目錄](docs/rules.md)） |
| `tools/paths.py` | 攻擊路徑查詢：起點與優先切斷的步驟、單一主體到 Tier0 的路徑、誰能取得某個物件 |
| `tools/mcp_server.py` | 唯讀 MCP 伺服器（stdio），讓地端模型查詢發現、關聯圖與攻擊路徑（[docs/mcp.md](docs/mcp.md)） |
| `tools/agent.py`、`tools/eval_agent.py` | 調查 Agent：地端模型（vLLM 等 OpenAI 相容 API）透過 MCP 產出中文報告，並以確定性檢查器驗證引用；比較多個模型（[docs/agent.md](docs/agent.md)） |
| `Dockerfile`、`compose.yaml` | lab 部署：單一映像、無網路的分析服務與只能看分析輸出的 Agent 服務（[docs/docker.md](docs/docker.md)） |
| `tests/powershell/` | 收集器的 mock 端對端測試 |
| `tests/python/` | 分析的合成環境測試（脆弱 / 乾淨兩套） |

## 快速開始

```powershell
# 子公司網域成員主機
.\collectors\powershell\Collect-ADHD.ps1 -Label SubA -TenantId sub-a.onmicrosoft.com
```

```bash
# lab（同一輪的 bundle 一起處理）
python3 tools/verify_bundle.py ADHD-Collect-SubA*<日期>*.zip
python3 tools/bundle_sanity.py ADHD-Collect-SubA*<日期>*.zip
python3 tools/analyze.py ADHD-Collect-SubA*<日期>*.zip --out reports/SubA-<日期>
```

收集說明見 [collectors/powershell/README.md](collectors/powershell/README.md)，分析說明見 [docs/analysis.md](docs/analysis.md)。

## 資料處理原則

- 只讀不寫；不收集任何密碼、雜湊、LAPS / BitLocker 金鑰或 App secret。
- 預設假名化，金鑰與對照表留在資料擁有者端。
- 收集前取得資料擁有者書面同意，明定用途、保存期限與銷毀方式。
- 收集到的 bundle 與分析輸出都不得提交到本 repo（`.gitignore` 已排除）。
