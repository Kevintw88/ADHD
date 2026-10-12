# 操作說明

適用版本：MVP 0.1.0（Phase 0+1，全程唯讀）。驗收步驟另見 [VERIFICATION.md](VERIFICATION.md)。

## 1. 運作方式

平台對每個法人（總公司、子公司）依序執行：

1. **盤點**：讀取 AD、Entra、工具與遙測現況，產出環境指紋。
2. **能力矩陣**：依 `config/capability_matrix.yaml` 判定 Profile（A 完整型 / B 部分型 / C 地端型）、可啟用模組、缺口、額外 Tier 0。
3. **攻擊路徑**：計算通往 Tier 0 的路徑，產出建議修補順序（每步實際移除後重算）。
4. **預防評估**：解析 PingCastle 報告，依「是否落在實際攻擊路徑上」排序。
5. **報告**：產出 Markdown 報告與 JSON 檔，每一步寫入稽核鏈。

以上全部是確定性程式，不需要模型。Agent 問答（`idsec ask`）是選用功能，經 LiteLLM 接地端模型，只能唯讀查詢。

## 2. 安裝

### 本機（開發、展示）

需求：Python 3.11 以上。

```bash
git clone https://github.com/Kevintw88/ADHD.git && cd ADHD
python -m venv .venv && source .venv/bin/activate      # Windows：.venv\Scripts\activate
pip install -e ".[dev,live]"
idsec --help
```

### Docker（總公司 Tier 0 隔離區）

```bash
cp docker/.env.example docker/.env            # 填 LITELLM_MASTER_KEY、VLLM_QWEN_BASE、VLLM_GLM_BASE
docker compose -f docker/docker-compose.yml --env-file docker/.env build
docker compose -f docker/docker-compose.yml --env-file docker/.env up -d litellm
```

以下所有 `idsec <指令>` 在 Docker 中改為：

```bash
docker compose -f docker/docker-compose.yml --env-file docker/.env run --rm idsec <指令>
```

容器以 uid 10001、唯讀根檔案系統執行，只有 `output/` 可寫。`config/` 以唯讀掛載，修改設定後不需重建映像。

## 3. 設定

### 3.1 `config/settings.yaml`

| 欄位 | 說明 |
| --- | --- |
| `output_dir` | 產出目錄，預設 `output` |
| `audit_log` | 稽核鏈檔案，預設 `output/audit/audit.jsonl` |
| `capability_matrix` | 能力矩陣規則檔 |
| `models.fast` / `models.reason` | LiteLLM 上的模型名稱；子代理 `discovery` 用 fast，其餘用 reason |
| `models.base_url` | LiteLLM 位址，可用環境變數 `ANTHROPIC_BASE_URL` 覆寫 |
| `entities` | 法人清單，見下節 |

### 3.2 新增法人

**模擬法人**（已內建 `hq`、`sub-a`、`sub-b`）：

```yaml
- id: hq
  name: 總公司（模擬）
  backend: mock
  data_dir: mock_data/hq
  reports_dir: mock_data/hq/reports
```

**實機法人**（先在 LAB 驗證）：

```yaml
- id: sub-x
  name: 子公司 X
  backend: live
  reports_dir: /data/reports/sub-x        # 放 PingCastle 的 ad_hc_<domain>.xml
  tooling_file: /data/tooling/sub-x.yaml  # 由 IT 填寫，範本 config/tooling.example.yaml
  ldap:
    server: dc01.subx.example
    base_dn: DC=subx,DC=example
    use_ssl: true
  graph:                                  # 沒有 Entra 租戶就整段省略
    tenant_id: <租戶 ID>
    client_id: <App ID>
    cert_path: /secrets/graph-readonly.pem
    cert_thumbprint: <憑證指紋>
  neo4j:                                  # 沒有 BloodHound CE 就省略（改用快照推導，缺 ACL 邊）
    uri: bolt://bloodhound-neo4j:7687
    user: neo4j
```

憑證只從環境變數讀取，不寫進設定檔：

| 環境變數 | 用途 |
| --- | --- |
| `IDSEC_LDAP_USER` / `IDSEC_LDAP_PASSWORD` | LDAP 唯讀帳號。`網域\帳號` 格式走 NTLM，否則走 Simple Bind |
| `IDSEC_GRAPH_SECRET` | Graph App 密碼（建議改用憑證，設定 `cert_path`） |
| `IDSEC_NEO4J_PASSWORD` | BloodHound Neo4j 唯讀帳號密碼 |
| `LITELLM_API_KEY` | LiteLLM 金鑰（`idsec ask` 需要） |

### 3.3 實機所需的唯讀權限

| 對象 | 權限 |
| --- | --- |
| AD | 一般網域使用者即可讀取所需屬性；建議專用帳號或 gMSA，不加入任何管理群組 |
| Entra（App 權限，需管理員同意） | `Directory.Read.All`、`Policy.Read.All`、`RoleManagement.Read.Directory`、`Application.Read.All`、`Organization.Read.All`；要讀 PIM 合格指派另需 `RoleEligibilitySchedule.Read.Directory` |
| BloodHound CE | Neo4j 唯讀帳號 |

### 3.4 `tooling_file`（LDAP / Graph 讀不到的部分）

由 IT 依 `config/tooling.example.yaml` 填寫：MDI、EDR、SIEM、各類日誌是否送入 SIEM、Sysmon 覆蓋率、AD FS 與 PTA 主機、DC 進階稽核原則。
稽核原則可在 DC 上執行 `auditpol /get /category:* /r` 後轉填。

### 3.5 調整能力矩陣

`config/capability_matrix.yaml` 決定 Profile 門檻、模組啟用條件、缺口與額外 Tier 0，修改後不需改程式。條件語法：

```yaml
when:
  all:
    - {path: hybrid.is_hybrid, eq: true}
    - {path: telemetry.coverage_score, gte: 0.6}
```

運算子：`eq ne gt gte lt lte in nonempty empty`，可用 `all` / `any` / `not` 巢狀。可用的路徑見 `idsec fingerprint <法人>` 的輸出。修改後執行 `idsec discover` 檢查判定結果。

## 4. 日常操作

### 4.1 標準流程

```bash
idsec discover sub-x        # 先看指紋、Profile、缺口；確認符合現況再往下
idsec run sub-x             # 完整流程與報告
idsec audit-verify          # 確認稽核鏈完整
```

省略法人代號即處理全部法人。

### 4.2 產出檔案（`output/<法人>/`）

| 檔案 | 內容 |
| --- | --- |
| `report.md` | 給人看的報告：重點、指紋、模組判定、缺口、修補順序、代表路徑、評估發現 |
| `fingerprint.json` | 環境指紋 |
| `capability.json` | Profile、啟用與未啟用模組（含原因）、缺口、額外 Tier 0 |
| `paths.json` | 攻擊路徑與修補順序 |
| `findings.json` | 已排序的評估發現 |

`output/` 含完整權限圖譜與弱點清單，依計畫書資料分級屬**極機密**：只放在 Tier 0 隔離區，依需知原則分發。

### 4.3 閱讀報告

- **重點**：可到達 Tier 0 的帳號比例，以及第一步修補可切斷多少。
- **建議修補順序**：依序執行；「修補後仍有路徑」降到 0 代表該法人所有已知路徑都被切斷。
- **缺口報告**：「影響模組」列出被這個缺口擋住的模組，先補擋住最多模組的缺口。
- **評估發現**：「排序理由」標示「出現在通往 Tier 0 的路徑上」的項目優先處理。

### 4.4 新子公司導入（先偵測、後運行）

1. IT 填寫 `tooling_file`，跑 PingCastle 並放入 `reports_dir`。
2. 在 `settings.yaml` 新增法人，執行 `idsec discover <法人>`。
3. 與子公司 IT 確認指紋與缺口是否符合現況（驗收方式見 VERIFICATION.md 的 V11）。
4. 確認後執行 `idsec run <法人>`，報告交子公司 IT 負責人。
5. 每季重跑 `idsec discover`，比對 `fingerprint.json` 與上次的差異。

## 5. Agent 問答（選用）

需要 LiteLLM 與地端模型，先完成 VERIFICATION.md 的 V10。

```bash
export ANTHROPIC_BASE_URL=http://litellm:4000
export LITELLM_API_KEY=<金鑰>
idsec agents hq                                   # 依能力矩陣列出可用子代理
idsec ask hq "哪些帳號能到達 Domain Admins？先修哪一條？"
idsec ask hq "總公司有哪些高風險的 Entra 應用程式？" --agent discovery
idsec ask sub-a "評估報告前三項要先處理什麼？修之前要確認什麼？" --agent assessment
```

| 子代理 | 適合的問題 | 使用模型 |
| --- | --- | --- |
| `discovery` | 盤點結果、缺口、Profile 判定理由 | fast |
| `assessment` | 評估發現的解讀、修補建議與相依性 | reason |
| `paths` | 攻擊路徑、某帳號能否到達 Tier 0、修補順序 | reason |

不指定 `--agent` 時由 Orchestrator 自行委派。注意事項：

- Agent 只能讀，回覆中的修補建議都要經人工審核才可執行。
- 回覆中的數字應與 `report.md` 一致；不一致時以報告為準，並回報給平台維護者。
- 回覆提到「疑似指令文字」時，代表 AD 或 Entra 某個物件的屬性含可疑內容，請人工檢查該物件。
- 執行時出現 `unrecognized_model` 警告可忽略，原因是 CLI 不認得地端模型名稱。

## 6. 單獨使用 MCP Server

四個唯讀 MCP Server 也可接到其他 MCP 用戶端（例如 Claude Code），以 stdio 啟動：

```json
{
  "mcpServers": {
    "idsec-bloodhound": {
      "command": "idsec",
      "args": ["mcp", "bloodhound"],
      "env": { "IDSEC_CONFIG": "/app/config/settings.yaml" }
    }
  }
}
```

可用的 server：`ad-discovery`、`entra-graph`、`bloodhound`、`assessment-reports`。每次工具呼叫都會寫入稽核鏈。

## 7. 稽核鏈

- 每次流程步驟、MCP 工具呼叫、Agent 問答與被拒絕的工具呼叫，都會附加一筆紀錄。每筆紀錄含前一筆的雜湊。
- `idsec audit-verify` 驗證整條鏈。失敗代表有紀錄被竄改、刪除或插入：
  1. **不要**刪除或修改檔案，先完整複製保存。
  2. 依錯誤訊息的筆數定位，比對前後紀錄的時間與操作者。
  3. 調查完成後再輪替：將檔案改名封存（例如 `audit-2026Q4.jsonl`），平台會自動開始新的鏈。
- 定期把封存檔複製到 WORM 儲存或 SIEM。

## 8. 疑難排解

| 現象 | 原因與處理 |
| --- | --- |
| `找不到模擬資料目錄` | 執行 `idsec mock-gen` |
| `找不到法人 'xxx'` | 法人代號未列在 `settings.yaml` 的 `entities` |
| `discover` 結果與現況不符 | 檢查 `tooling_file` 是否已填寫、是否為最新；稽核原則或 Sysmon 若顯示「未知」，代表檔案未提供 |
| 路徑數明顯偏少 | 未設定 `neo4j`，改用快照推導圖譜，缺少 ACL 與 Session 邊；請接 BloodHound CE |
| LDAP 連線失敗 | 確認 636 埠可達、DC 憑證受信任；帳號格式 `網域\帳號` 走 NTLM |
| Graph 回 403 | App 缺權限或未完成管理員同意，對照 3.3 節 |
| `idsec ask` 連線失敗 | 確認 `ANTHROPIC_BASE_URL`；用 `curl $ANTHROPIC_BASE_URL/health/liveliness` 檢查 LiteLLM |
| Agent 不呼叫工具或回覆數字錯誤 | 模型的 tool use 能力或格式不相容，執行 VERIFICATION.md 的 V10；可在 `settings.yaml` 調換 fast 與 reason 模型 |
| Docker 內寫檔失敗 | 只有 `output/` 可寫，確認已掛載且 uid 10001 有寫入權限 |
| `audit-verify` 失敗 | 見第 7 節，先保全證據 |

## 9. 安全注意事項

- 所有存取帳號只給唯讀權限；不要為了「方便」使用 Domain Admins 或具寫入權限的 Graph App。
- `output/` 與稽核鏈屬極機密。AI 平台本身視同 Tier 0：管理員使用專用工作站，存取需稽核。
- 自建或修改 MCP Server、Skills 後，上線前送內部 Skill 安全檢測平台掃描，並重跑 `scripts/verify_mvp.py`。
- MVP 不執行任何變更。報告中的修補建議須經變更流程與人工審核閘門。
