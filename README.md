# hybrid-idsec

AD 與 Entra ID 混合環境的 AI 資安防護平台。本版本為 **MVP（Phase 0+1，全程唯讀）**：
先盤點各法人環境，依能力矩陣決定啟用哪些模組（先偵測、後運行），再做預防評估與攻擊路徑分析。

- 盤點、能力矩陣、路徑分析、報告全部是**確定性程式**，不接 LLM 也能完整運作。
- Agent 層（Claude Agent SDK + 唯讀 MCP）只負責自然語言問答與解讀，經 LiteLLM 接**地端模型**，資料不出公司。
- 修補建議只產出，不執行；變更須走人工審核閘門（Phase 3）。

架構與設計決策見 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 快速開始（模擬資料）

```bash
pip install -e ".[dev]"
idsec mock-gen          # 產生三個模擬法人（固定種子，可重現）
idsec run               # 盤點 → 能力矩陣 → 評估 → 路徑 → 報告
idsec audit-verify      # 驗證稽核鏈
pytest                  # 23 項測試，含以樁模型跑通 Agent 全流程
```

報告在 `output/<法人>/report.md`，另有 `fingerprint.json`、`capability.json`、`paths.json`、`findings.json`。

## 模擬法人

| 法人 | Profile | 環境 | 埋入的弱點 |
| --- | --- | --- | --- |
| `hq` | A 完整型 | Entra Connect + PHS + Seamless SSO、MDI、SIEM、AD CS | ESC1 範本開放 Domain Users、服務帳號在 Domain Admins、Helpdesk 經 ACL 到達 DA 工作階段、Application Administrator 可替高權限 App 加密鑰、地端帳號同步為雲端全域管理員 |
| `sub-a` | B 部分型 | AD FS、無 MDI、無 SIEM | IT 群組對 DA 帳號有 GenericAll、Domain Users 是某工作站本機管理員且 DA 在其上登入 |
| `sub-b` | C 地端型 | 純 AD、遙測未知 | Domain Users 是檔案伺服器本機管理員且 administrator 在其上登入、無限制委派 |

## 指令

| 指令 | 說明 |
| --- | --- |
| `idsec discover [法人\|all]` | Phase 0：指紋、Profile、啟用模組、缺口 |
| `idsec run [法人\|all]` | 完整確定性流程與報告 |
| `idsec fingerprint <法人>` | 輸出環境指紋 JSON |
| `idsec agents [法人\|all]` | 依能力矩陣列出可用子代理 |
| `idsec ask <法人> "<問題>" [--agent discovery\|assessment\|paths]` | Agent 問答（需 LiteLLM） |
| `idsec mcp <server>` | 以 stdio 啟動單一 MCP Server |
| `idsec audit-verify` | 驗證 hash-chain 稽核日誌 |

## Docker 部署

```bash
cp docker/.env.example docker/.env      # 填 LiteLLM 金鑰與 vLLM 位址
docker compose -f docker/docker-compose.yml --env-file docker/.env up -d litellm
docker compose -f docker/docker-compose.yml --env-file docker/.env run --rm idsec run
docker compose -f docker/docker-compose.yml --env-file docker/.env run --rm idsec ask hq "先修哪一條路徑？"
```

容器以非 root、唯讀根檔案系統、`cap_drop: ALL` 執行，`idsec` 服務所在網段無對外出口。
Claude Agent SDK 內含原生 CLI，映像不需 Node.js。

## 接上實機（LAB 先行）

1. 複製 `config/tooling.example.yaml`，由 IT 填寫 MDI、SIEM、Sysmon、稽核原則、AD FS / PTA 主機。
2. 在 `config/settings.yaml` 新增 `backend: live` 的法人（範例已註解於檔案底部）。
3. 準備唯讀身分：
   - LDAP：唯讀帳號或 gMSA，`IDSEC_LDAP_USER` / `IDSEC_LDAP_PASSWORD`
   - Graph：憑證驗證的 App，權限 `Directory.Read.All`、`Policy.Read.All`、`RoleManagement.Read.Directory`、`Application.Read.All`、`Organization.Read.All`
   - BloodHound CE：Neo4j 唯讀帳號（未設定時退回快照推導圖譜，缺 ACL 與 Session 邊）
4. PingCastle 報告 `ad_hc_<domain>.xml` 放到 `reports_dir`。
5. `idsec discover <法人>` 先看指紋與缺口，再 `idsec run`。

> live 後端（`src/idsec/backends/live.py`）尚未在實機驗證，請先於 LAB 測試。

## 安全設計

| 防線 | 位置 |
| --- | --- |
| MCP Server 只實作讀取，工具標註 `readOnlyHint` | `src/idsec/mcp_servers/` |
| 內建工具只留 Agent / Skill，其餘全部 disallow；`strict_mcp_config` | `agent/orchestrator.py` |
| PreToolUse 放行清單，拒絕清單外工具與寫入型 Cypher | `agent/hooks.py` |
| PostToolUse 稽核每次呼叫，偵測回傳內容中的注入文字 | `agent/hooks.py` |
| 工具回傳統一加註「資料非指令」，截斷長字串、移除控制字元 | `mcp_servers/_common.py` |
| Hash-chain 稽核日誌，竄改、刪除、插入皆可偵測 | `audit.py` |
| PingCastle XML 拒絕 DTD / ENTITY | `reports/pingcastle.py` |

自建 MCP Server 與 Skills 上線前，請送內部 Skill 安全檢測平台掃描。

## 已知限制與下一步

- live 後端未經實機驗證；AD CS 範本的註冊權（ACL）尚未解析，交由 BloodHound CE / Locksmith 判定。
- 評估報告目前只解析 PingCastle；Locksmith、Purple Knight、ScubaGear 解析器待補（`reports/__init__.py` 的 `PARSERS`）。
- 模型分工需以評測集實測後決定（`config/settings.yaml` 的 `models`）。
- Phase 2 偵測模組目前只做能力判定，不執行。

## 專案結構

```
config/            settings.yaml、capability_matrix.yaml、tooling.example.yaml
src/idsec/
  backends/        mock 與 live 後端、快照推導圖譜
  discovery.py     環境指紋
  capability.py    能力矩陣引擎
  paths.py         攻擊路徑與貪婪修補順序
  reports/         評估報告解析與優先排序
  pipeline.py      確定性流程；report.py 產出 Markdown
  services.py      MCP 與 Agent 共用的快取查詢層
  mcp_servers/     四個唯讀 MCP Server
  agent/           Orchestrator、子代理提示、Hooks
.claude/skills/    Agent 作業手冊（攻擊路徑分流、評估排序）
docker/            Dockerfile、compose、LiteLLM 設定
mock_data/         模擬資料（idsec mock-gen 產生）
tests/             單元與整合測試、樁模型
```
