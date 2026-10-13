"""產生最新版架構圖：docs/diagrams/architecture.svg（hex 色，給 repo 與簡報）與 widget JSX（給計畫書）。

同一份幾何資料輸出兩種格式，避免兩張圖不一致。
用法：python docs/diagrams/gen_architecture.py
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).parent
W, H = 760, 856
TITLE = "規則決定啟用什麼，AI 只讀不寫，所有變更經人工審核"

# (anchor id, x, y, w, h, name, body, style)  style: box / accent / dashed
CONTAINERS = [
    ("sources", 24, 52, 712, 104, "資料來源（各法人，唯讀存取）", "solid"),
    ("core", 24, 252, 348, 324, "確定性核心（不需 LLM 即可完整運作）", "solid"),
    ("ai", 388, 252, 348, 324, "AI 層（選用，只能唯讀查詢）", "solid"),
    ("review", 24, 600, 712, 104, "Review 與治理", "tint"),
    ("future", 24, 728, 712, 104, "Phase 2–3 規劃中", "dashed"),
]
BOXES = [
    ("src-ad", 40, 84, 120, 56, "地端 AD", "LDAP 唯讀", "box"),
    ("src-entra", 180, 84, 120, 56, "Entra ID", "Graph 唯讀", "box"),
    ("src-bh", 320, 84, 120, 56, "BloodHound CE", "Neo4j 唯讀", "box"),
    ("src-report", 460, 84, 120, 56, "評估報告", "PingCastle XML", "box"),
    ("src-tooling", 600, 84, 120, 56, "IT 現況檔", "tooling.yaml", "box"),
    ("backend", 24, 180, 712, 48, "後端抽象：mock / live → 正規化資料模型", None, "box"),
    ("core-discovery", 40, 288, 316, 56, "1 盤點與環境指紋", "指紋 JSON：AD・混合同步・身分・遙測", "box"),
    ("core-matrix", 40, 360, 316, 56, "2 能力矩陣（YAML 規則）", "Profile・啟用模組・缺口・額外 Tier 0", "accent"),
    ("core-paths", 40, 432, 150, 56, "3a 攻擊路徑", "貪婪修補・每步重算", "box"),
    ("core-assess", 206, 432, 150, 56, "3b 評估排序", "落在路徑上加權", "box"),
    ("core-report", 40, 504, 316, 56, "4 報告與 JSON 產出", "數字全來自工具，不經 LLM 改寫", "box"),
    ("ai-mcp", 404, 288, 316, 56, "唯讀 MCP Servers ×4", "18 個工具，皆標註 readOnlyHint", "box"),
    ("ai-hooks", 404, 360, 316, 56, "Hooks 防線", "放行清單・寫入攔截・注入偵測", "box"),
    ("ai-orch", 404, 432, 316, 56, "Orchestrator + 子代理", "依能力矩陣掛載 discovery・assessment・paths", "box"),
    ("ai-llm", 404, 504, 316, 56, "LiteLLM → 地端 vLLM", "qwen3.8-flash-next・glm 5.3 flash", "box"),
    ("rv-gate", 40, 632, 158, 56, "人工審核閘門", "L0 自動 → L3 雙人核准", "accent"),
    ("rv-audit", 214, 632, 158, 56, "稽核鏈", "hash-chain 防竄改", "box"),
    ("rv-verify", 388, 632, 158, 56, "驗證與評測", "V1–V11・模型評測集", "box"),
    ("rv-rules", 562, 632, 158, 56, "規則與 Skill 審查", "PR 審核・安全掃描", "box"),
    ("ft-siem", 40, 760, 158, 56, "SIEM 偵測分流", "MDI・Sigma 規則", "dashed"),
    ("ft-rules", 214, 760, 158, 56, "偵測規則庫", "Git PR・CI 測試", "dashed"),
    ("ft-soar", 388, 760, 158, 56, "SOAR 執行", "核准後・可回滾", "dashed"),
    ("ft-bas", 562, 760, 158, 56, "持續驗證", "BAS・紫隊演練", "dashed"),
]
# (path d, dashed)
ARROWS = [
    ("M380 156V179", False),
    ("M198 228V251", False),
    ("M562 228V251", False),
    ("M198 344V359", False),
    ("M198 416V424H115V431", False),
    ("M198 416V424H281V431", False),
    ("M115 488V496H198V503", False),
    ("M281 488V496H198V503", False),
    ("M562 344V359", False),
    ("M562 416V431", False),
    ("M562 488V503", False),
    ("M356 388H380V460H403", False),   # 能力矩陣 → 決定掛載哪些子代理
    ("M198 576V599", False),
    ("M562 576V599", False),
    ("M119 688V716H467V759", True),    # 人工核准 → SOAR 執行（規劃中）
]
LABELS: list = []  # (id, x, y, text, anchor)；線段間隙窄，關係改在圖說說明

HEX = {"ink": "1F2937", "quiet": "5B6472", "edge": "8A94A3", "accent": "0E8F7E", "tint": "EEF2F6"}
FONT = "Microsoft JhengHei, Noto Sans CJK TC, Noto Sans CJK HK, sans-serif"


def _box_text(cx, y0, h, name, body):
    if body is None:
        return [(cx, y0 + h / 2 + 4.5, name, 13, 600, "ink")]
    return [(cx, y0 + 24, name, 13, 600, "ink"), (cx, y0 + 42, body, 11.5, 400, "quiet")]


def svg() -> str:
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W * 2}" height="{H * 2}" '
         f'font-family="{FONT}" role="img" aria-label="{TITLE}">',
         f'<rect width="{W}" height="{H}" fill="#FFFFFF"/>',
         '<defs><marker id="arch-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" '
         f'orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#{HEX["edge"]}"/></marker></defs>',
         f'<text x="24" y="30" font-size="15" font-weight="600" fill="#{HEX["ink"]}">{TITLE}</text>']
    for cid, x, y, w, h, name, style in CONTAINERS:
        fill = f'#{HEX["tint"]}' if style == "tint" else "none"
        dash = ' stroke-dasharray="5 4"' if style == "dashed" else ""
        o.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{fill}" stroke="#{HEX["edge"]}" stroke-width="1"{dash}/>')
        o.append(f'<text x="{x + 16}" y="{y + 22}" font-size="13" font-weight="600" fill="#{HEX["ink"]}">{name}</text>')
    for bid, x, y, w, h, name, body, style in BOXES:
        if style == "accent":
            o.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="#{HEX["accent"]}" fill-opacity="0.12" '
                     f'stroke="#{HEX["accent"]}" stroke-width="2"/>')
        else:
            dash = ' stroke-dasharray="5 4"' if style == "dashed" else ""
            o.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="#FFFFFF" stroke="#{HEX["edge"]}" stroke-width="1.25"{dash}/>')
        for tx, ty, text, size, weight, color in _box_text(x + w / 2, y, h, name, body):
            o.append(f'<text x="{tx}" y="{ty}" text-anchor="middle" font-size="{size}" font-weight="{weight}" fill="#{HEX[color]}">{text}</text>')
    for d, dashed in ARROWS:
        dash = ' stroke-dasharray="5 4"' if dashed else ""
        o.append(f'<path d="{d}" fill="none" stroke="#{HEX["edge"]}" stroke-width="1.25" marker-end="url(#arch-arrow)"{dash}/>')
    for lid, x, y, text, anchor in LABELS:
        o.append(f'<text x="{x}" y="{y}" text-anchor="{anchor}" font-size="11.5" fill="#{HEX["quiet"]}" '
                 f'stroke="#FFFFFF" stroke-width="3" paint-order="stroke">{text}</text>')
    o.append("</svg>")
    return "\n".join(o)


def jsx() -> str:
    tok = {"ink": "var(--cds-text-primary)", "quiet": "var(--cds-text-secondary)", "edge": "var(--cds-chart-axis)",
           "accent": "var(--cds-chart-categorical-1)", "tint": "var(--cds-chart-reference-tint)"}
    o = [f"<svg viewBox='0 0 {W} {H}' role='img' aria-label='{TITLE}' fontSize='13'>",
         "<defs><marker id='arch2-arrow' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='6' markerHeight='6' "
         f"orient='auto-start-reverse'><path d='M0 0L10 5L0 10z' fill='{tok['edge']}'/></marker></defs>",
         f"<text data-claude-text-id='title' x='24' y='30' fontSize='15' fontWeight='600' fill='{tok['ink']}'>{TITLE}</text>"]
    for cid, x, y, w, h, name, style in CONTAINERS:
        fill = tok["tint"] if style == "tint" else "none"
        dash = " strokeDasharray='5 4'" if style == "dashed" else ""
        o.append(f"<g data-claude-anchor='{cid}'><rect x='{x}' y='{y}' width='{w}' height='{h}' rx='8' fill='{fill}' "
                 f"stroke='{tok['edge']}' strokeWidth='1'{dash}/><text data-claude-text-id='{cid}-name' x='{x + 16}' "
                 f"y='{y + 22}' fontWeight='600' fill='{tok['ink']}'>{name}</text></g>")
    for bid, x, y, w, h, name, body, style in BOXES:
        if style == "accent":
            rect = (f"<rect x='{x}' y='{y}' width='{w}' height='{h}' rx='8' fill='{tok['accent']}' fillOpacity='0.12' "
                    f"stroke='{tok['accent']}' strokeWidth='2'/>")
        else:
            dash = " strokeDasharray='5 4'" if style == "dashed" else ""
            rect = (f"<rect x='{x}' y='{y}' width='{w}' height='{h}' rx='8' fill='none' stroke='{tok['edge']}' "
                    f"strokeWidth='1.25'{dash}/>")
        texts = []
        for i, (tx, ty, text, size, weight, color) in enumerate(_box_text(x + w / 2, y, h, name, body)):
            tid = bid if i == 0 else f"{bid}-body"
            fw = f" fontWeight='{weight}'" if weight != 400 else ""
            fs = f" fontSize='{size}'" if size != 13 else ""
            texts.append(f"<text data-claude-text-id='{tid}' x='{tx}' y='{ty}' textAnchor='middle'{fs}{fw} "
                         f"fill='{tok[color]}'>{text}</text>")
        o.append(f"<g data-claude-anchor='{bid}'>{rect}{''.join(texts)}</g>")
    paths = []
    for d, dashed in ARROWS:
        dash = " strokeDasharray='5 4'" if dashed else ""
        paths.append(f"<path d='{d}' markerEnd='url(#arch2-arrow)'{dash}/>")
    o.append(f"<g data-claude-anchor='connectors' fill='none' stroke='{tok['edge']}' strokeWidth='1.25'>{''.join(paths)}</g>")
    for lid, x, y, text, anchor in LABELS:
        o.append(f"<text data-claude-text-id='{lid}' x='{x}' y='{y}' textAnchor='{anchor}' fontSize='11.5' "
                 f"fill='{tok['quiet']}'>{text}</text>")
    o.append("</svg>")
    return "export default () => " + "".join(o) + ";"


if __name__ == "__main__":
    (HERE / "architecture.svg").write_text(svg(), encoding="utf-8")
    (HERE / "architecture.widget.jsx").write_text(jsx(), encoding="utf-8")
    print(json.dumps({"svg": str(HERE / "architecture.svg"), "jsx_chars": len(jsx())}))
