# MCP 伺服器（唯讀）

讓地端模型（或任何 MCP 用戶端）查詢一次分析的結果：發現、規則狀態、關聯圖與攻擊路徑。只用 Python 標準函式庫，透過 stdio 溝通（MCP 2025-06-18，也相容 2025-03-26 與 2024-11-05），可以直接在隔離的分析主機上執行。

```bash
python3 tools/analyze.py <同一輪的 bundles> --out /srv/adhd/reports/SubA-20261020
python3 tools/mcp_server.py /srv/adhd/reports/SubA-20261020
```

伺服器只讀分析輸出（`findings.json`、`graph.sqlite`），不讀原始 bundle，也不需要假名化金鑰：模型看到的都是假名（`u-xxxxxxxxxxxx`），與報告相同。需要分析器 0.3.0 以後的輸出（攻擊路徑相關工具需要 `attack_steps` / `attack_paths` 表）。

## 工具

| 工具 | 用途 |
|---|---|
| `get_overview` | 範圍、資料時間、各嚴重度發現數、規則狀態（含哪些規則因資料不足而略過）、Tier0 數、攻擊路徑摘要、重點對象。建議第一個呼叫 |
| `list_findings` | 依嚴重度排序的發現；可依最低嚴重度、規則代號前綴（`AD-02`、`HY`）、類別或文字（含受影響對象）篩選，可分頁 |
| `get_finding` | 單筆發現：摘要、受影響對象與細節、證據、修補建議、ATT&CK |
| `list_rules` | 每條規則的狀態；`skipped` 會寫明缺少哪些資料集 |
| `get_hotspots` | 出現在多條規則的身分（AD 帳號與其同步的 Entra 帳號合併計分） |
| `search_nodes` | 以名稱或 id 片段找物件，可限定類型與是否為 Tier0 |
| `get_node` | 單一物件的屬性、是否為 Tier0 與原因、列出它的發現、關係數量 |
| `get_edges` | 單一物件的關係（成員、ACL 權限、委派、GPO 連結、同步、角色），`out` = 它能做什麼，`in` = 誰對它有權限 |
| `list_attack_paths` | 通往 Tier0 的起點（廣泛群組優先），以及優先切斷的步驟 |
| `path_to_tier0` | 某個主體到 Tier0 的最短路徑，逐步列出 |
| `who_can_reach` | 誰能取得某個物件（例如同步的雲端管理員、Entra Connect 伺服器），各附最短路徑 |

`node` 參數可以填 id（SID、`entra:<objectId>`、`dn:…`、`gpo:…`）或完整名稱；名稱對到多個物件時，工具會回傳候選清單請模型改用 id。

每個結果同時以 JSON 文字與 `structuredContent` 回傳（2025-06-18）；單次結果超過約 6 萬字元時，最長的清單會被截短並標示 `truncated`。

## 給模型的規則

伺服器在 `initialize` 的 `instructions` 中告訴模型：

- 發現是確定性規則的結果並附證據：據實引用，不自行判斷「有沒有問題」，也不推測資料中沒有的內容；
- 每個陳述都引用 `findingId` 與 `ruleId`；
- 狀態為 `skipped` 的規則是「未評估」，不可寫成「通過」；
- 帳號名稱是假名，照原樣使用；
- 攻擊路徑是每個起點最短的一條，可能還有其他較長的路徑。

## 安全性

- **唯讀**：SQLite 以 `mode=ro` 開啟；沒有任意 SQL、檔案或網路存取的工具；所有工具都標示 `readOnlyHint`。
- **只走 stdio**：不開網路埠。需要跨主機時，在 lab 內以有存取控制的方式包裝（之後的 Docker 階段處理），不要直接對外。
- **資料範圍**：只有分析輸出，與報告一樣含環境資訊（假名化），只在 lab 內使用，不送到雲端服務。

## 測試

```bash
python3 -m unittest tests/python/test_mcp.py -v
```

涵蓋協定處理（版本協商、錯誤碼、通知、stdio 往返）、每個工具、唯讀保證。若環境裝有官方 MCP Python SDK（`pip install mcp`），會另外以官方用戶端透過 stdio 連線測試互通性；沒裝則略過。
