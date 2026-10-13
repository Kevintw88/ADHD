# 簡報

| 檔案 | 對象 | 頁數 |
| --- | --- | --- |
| `hybrid-idsec-技術架構.pptx` | 資安、AD、IAM、SOC 技術團隊：架構、規則機制、Review 機制、部署 | 22 |
| `AD-Entra-AI資安防護-管理簡報.pptx` | 管理層：AD 風險、做法、模擬結果、AI 效益、治理、決策請求 | 14 |

兩份簡報皆含講者備註。由程式產生，修改內容請改產生器後重建：

```bash
cd docs/slides
node build_tech.js hybrid-idsec-技術架構.pptx
node build_mgmt.js AD-Entra-AI資安防護-管理簡報.pptx
```

`lib.js` 為共用主題（色彩、版面、圖示），中文字型為微軟正黑體。架構圖原始檔在 `docs/diagrams/`（`python docs/diagrams/gen_architecture.py` 重新產生 SVG）。

簡報中的模擬數字來自 `idsec run` 對 `mock_data/` 的實跑結果；修改規則或模擬資料後請一併更新。
