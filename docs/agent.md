# 調查 Agent（地端模型）

讓地端模型透過[唯讀 MCP 伺服器](mcp.md)查詢一次分析的結果，產出中文報告或回答問題；報告寫完後，由確定性的檢查器比對分析結果，有問題就請模型修正一次。只用 Python 標準函式庫，模型端點是 lab 內的 OpenAI 相容 API（vLLM、SGLang、Ollama 等），資料不會離開 lab。

```
analyze.py ─▶ findings.json / graph.sqlite ─▶ mcp_server.py（唯讀工具）
                                                   ▲  tools/call
                                  agent.py ── 工具迴圈 ── 地端模型（vLLM）
                                     │
                                     └▶ verify.py：引用 / 假名 / 覆蓋率檢查 ─▶ 未通過則回饋修正一次
```

設計依照 Anthropic〈Building effective agents〉的建議，用最簡單、可組合的模式：

- **augmented LLM**：一個模型 + 工具迴圈，MCP 工具是它看資料的唯一管道；
- **evaluator-optimizer**：報告交給 `adhd/verify.py` 檢查，未通過時把問題清單交回模型修正（預設一次）。

## 準備模型服務（vLLM）

模型服務必須開啟工具呼叫（function calling）：

```bash
vllm serve <模型路徑或名稱> --served-model-name <名稱> \
    --enable-auto-tool-choice --tool-call-parser <符合模型的 parser> \
    --max-model-len 65536
```

`--tool-call-parser` 要和模型相符（例如 Qwen 系列常用 `hermes`、GLM 系列常用 `glm45`；新版本模型請以 vLLM 文件為準）。若模型會輸出思考內容，`<think>…</think>` 會被自動去除，也可以在 vLLM 加上對應的 `--reasoning-parser`。Context 長度建議 32K 以上：工具結果每次最多傳給模型 12,000 字元。

## 使用

```bash
# 1. 分析（產生 findings.json 與 graph.sqlite）
python3 tools/analyze.py <同一輪的 bundles> --out /srv/adhd/reports/SubA-20261020

# 2. 產出報告
python3 tools/agent.py --report-dir /srv/adhd/reports/SubA-20261020 \
    --base-url http://gpu01:8000/v1 --model <served-model-name> --task report

# 3. 問問題（不做報告檢查）
python3 tools/agent.py --report-dir ... --model ... --task "誰能取得 Entra Connect 伺服器？路徑是什麼？"

# 只檢查一份既有報告
python3 tools/agent.py --report-dir ... --verify-only answer.md
```

輸出在 `<report-dir>/agent-<時間>/`：

| 檔案 | 內容 |
|---|---|
| `answer.md` | 報告或回答 |
| `verification.json` | 檢查結果（報告任務才有） |
| `transcript.jsonl` | 每次模型回應、工具呼叫（含參數與結果）、檢查結果：稽核用 |

`--base-url`、`--model`、`--api-key` 也可用環境變數 `ADHD_LLM_BASE_URL`、`ADHD_LLM_MODEL`、`ADHD_LLM_API_KEY` 設定。

## 報告檢查（adhd/verify.py）

| 檢查 | 等級 | 說明 |
|---|---|---|
| `unknown_finding` | 錯誤 | 引用的 `F###` 不存在 |
| `wrong_rule` | 錯誤 | `F### / 規則代號` 配對不符 |
| `unknown_rule` | 錯誤 | 規則代號不存在 |
| `missing_critical` | 錯誤 | 有嚴重（critical）發現沒有被引用 |
| `unknown_name` / `unknown_sid` | 錯誤 | 假名或 SID 不在分析資料中（捏造的帳號） |
| `skipped_as_passed` | 錯誤 | 因資料不足未評估的規則被寫成通過 |
| `no_scope_note` | 警告 | 有未評估的規則，但報告沒有說明未評估的範圍 |
| `uncited_claim` | 警告 | 描述風險的段落沒有引用任何發現 |

另外回報高嚴重度發現的引用比例（`highCoverage`）。檢查是確定性的、不需要模型，但只能抓「格式化可驗證」的錯誤：數字或敘述與證據不符這類問題仍需要人工審閱。

## 比較模型

```bash
python3 tools/eval_agent.py --report-dir /srv/adhd/reports/SubA-20261020 \
    --base-url http://gpu01:8000/v1 --model <qwen 名稱> --model <glm 名稱> --runs 3
# 兩個模型在不同的 vLLM：--base-url-for <名稱>=http://gpu02:8000/v1
```

每個模型跑 N 次報告任務，列出通過率、平均錯誤數、高嚴重度覆蓋率、平均秒數與工具呼叫次數，並保存每次的 `answer.md`、`verification.json`、`transcript.jsonl`。

## 安全性與資料

- 模型只能用 MCP 的唯讀工具；沒有寫入、檔案、網路或任意 SQL 的工具。
- 同一個查詢重複超過兩次會被擋下，避免模型卡在迴圈；最多 30 步（`--max-steps`）。
- `answer.md` 與 `transcript.jsonl` 含環境資訊（假名化），和報告一樣只在 lab 內保存，不提交到 repo，不送到雲端服務。

## 限制

- 品質取決於模型的工具呼叫能力；目前只以模擬模型測試過流程，尚未以實際的 qwen / glm 模型評估。
- 檢查器以規則比對，能抓出捏造的發現、帳號與漏掉的嚴重發現，但不保證敘述完全正確。
