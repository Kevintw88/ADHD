// 技術導向簡報：hybrid-idsec 技術架構（重點：規則與 Review 機制）
const pptxgen = require("pptxgenjs");
const L = require("./lib.js");
const { HEX } = L;

const OUT = process.argv[2] || "hybrid-idsec-技術架構.pptx";

(async () => {
  const pres = new pptxgen();
  const C = L.setup(pres, "hybrid-idsec 技術架構｜v0.1（Phase 0+1）");
  pres.title = "hybrid-idsec 技術架構";

  const content = (section, title) => {
    const s = pres.addSlide({ masterName: "CONTENT", sectionTitle: section });
    s.addText(title, { placeholder: "title" });
    return s;
  };
  const text = (s, t, o) => s.addText(t, { isTextBox: true, margin: 0, color: HEX.dk1, fontSize: 14, valign: "top", ...o });

  // ================================================================ 開場
  pres.addSection({ title: "開場" });
  {
    const s = pres.addSlide({ masterName: "TITLE_DARK", sectionTitle: "開場" });
    s.addText("hybrid-idsec 技術架構", { placeholder: "title" });
    s.addText("AD + Entra ID 混合環境 AI 資安防護平台\n規則驅動・唯讀・可審核｜v0.1（Phase 0+1）", { placeholder: "body" });
    s.addNotes("本簡報說明 v0.1 的實作架構，重點放在兩件事：能力矩陣規則如何決定每個法人啟用什麼，以及從設計到事後的多層 Review 機制。");
  }
  {
    const s = content("開場", "一頁看懂：規則決定做什麼，AI 只負責解釋");
    const cols = [
      ["TbAdjustmentsHorizontal", "先偵測、後運行", "盤點產出環境指紋，能力矩陣（YAML 規則）據此判定 Profile、啟用模組與缺口。新增或調整規則不需改程式。"],
      ["TbBinaryTree", "確定性優先", "攻擊路徑、弱點排序、報告全由程式計算。LLM 只做自然語言解釋與問答，報告不經 LLM 改寫。"],
      ["TbShieldCheck", "多層 Review", "設計時審規則、執行時四道防線、產出時人工審核分級、事後以 hash-chain 稽核鏈與 V1–V11 驗證追溯。"],
    ];
    for (let i = 0; i < 3; i++) {
      const x = 0.6 + i * 4.1;
      L.card(pres, s, x, 1.45, 3.85, 3.25, { name: `pillar-${i}` });
      await L.badge(pres, s, x + 0.3, 1.7, 0.7, cols[i][0], HEX.accent1, `pillar-${i}`);
      text(s, cols[i][1], { x: x + 0.3, y: 2.6, w: 3.3, h: 0.45, fontSize: 20, bold: true });
      text(s, cols[i][2], { x: x + 0.3, y: 3.1, w: 3.3, h: 1.5, fontSize: 14, color: HEX.muted });
    }
    const stats = [["3", "種 Profile 自動判定"], ["18", "個 MCP 工具，全部唯讀"], ["4", "道獨立防線"], ["23 + 7", "項測試與驗收全數通過"]];
    for (let i = 0; i < 4; i++) {
      const x = 0.6 + i * 3.08;
      text(s, stats[i][0], { x, y: 5.0, w: 2.9, h: 0.9, fontSize: 44, bold: true, color: HEX.accent1 });
      text(s, stats[i][1], { x, y: 5.9, w: 2.9, h: 0.5, fontSize: 14, color: HEX.muted });
    }
    s.addNotes("三個設計原則對應三個問題：每個法人做什麼（規則）、結果可不可信（確定性）、AI 會不會闖禍（Review）。底部數字皆來自 v0.1 實測：pytest 23 項、verify_mvp.py 7 項。");
  }
  {
    const s = content("開場", "系統架構：五層，兩個控制點");
    // 資料來源
    const src = [["地端 AD", "LDAP 唯讀"], ["Entra ID", "Graph 唯讀"], ["BloodHound CE", "Neo4j 唯讀"], ["評估報告", "PingCastle XML"], ["IT 現況檔", "tooling.yaml"]];
    src.forEach(([t, sub], i) => L.box(pres, s, 0.6 + i * 1.78, 1.4, 1.6, 0.7, t, sub, { name: `src-${i}` }));
    L.arrow(pres, s, 4.95, 2.1, 4.95, 2.27);
    L.box(pres, s, 0.6, 2.27, 8.7, 0.42, "後端抽象：mock / live → 正規化資料模型", null, { name: "backend" });
    L.arrow(pres, s, 2.72, 2.69, 2.72, 2.86); L.arrow(pres, s, 7.18, 2.69, 7.18, 2.86);
    // 確定性核心
    L.card(pres, s, 0.6, 2.86, 4.25, 2.75, { fill: "FFFFFF", line: HEX.line, name: "core" });
    text(s, "確定性核心（不需 LLM）", { x: 0.75, y: 2.93, w: 4, h: 0.3, fontSize: 12, bold: true, color: HEX.muted });
    L.box(pres, s, 0.75, 3.3, 1.9, 0.95, "1 盤點與指紋", "環境指紋 JSON", { name: "c1" });
    L.box(pres, s, 2.8, 3.3, 1.9, 0.95, "2 能力矩陣", "YAML 規則", { style: "accent", name: "c2" });
    L.box(pres, s, 2.8, 4.5, 1.9, 0.95, "3 路徑＋評估", "修補順序・排序", { name: "c3" });
    L.box(pres, s, 0.75, 4.5, 1.9, 0.95, "4 報告產出", "不經 LLM 改寫", { name: "c4" });
    L.arrow(pres, s, 2.65, 3.775, 2.8, 3.775); L.arrow(pres, s, 3.75, 4.25, 3.75, 4.5); L.arrow(pres, s, 2.8, 4.975, 2.65, 4.975);
    // AI 層
    L.card(pres, s, 5.05, 2.86, 4.25, 2.75, { fill: "FFFFFF", line: HEX.line, name: "ai" });
    text(s, "AI 層（選用，只能唯讀）", { x: 5.2, y: 2.93, w: 4, h: 0.3, fontSize: 12, bold: true, color: HEX.muted });
    L.box(pres, s, 7.25, 3.3, 1.9, 0.95, "唯讀 MCP ×4", "18 個工具", { style: "blue", name: "a1" });
    L.box(pres, s, 5.2, 3.3, 1.9, 0.95, "Hooks 防線", "放行・稽核・注入", { style: "blue", name: "a2" });
    L.box(pres, s, 5.2, 4.5, 1.9, 0.95, "Orchestrator", "子代理 ×3", { style: "blue", name: "a3" });
    L.box(pres, s, 7.25, 4.5, 1.9, 0.95, "地端模型", "LiteLLM → vLLM", { style: "blue", name: "a4" });
    L.arrow(pres, s, 7.25, 3.775, 7.1, 3.775); L.arrow(pres, s, 6.15, 4.25, 6.15, 4.5); L.arrow(pres, s, 7.1, 4.975, 7.25, 4.975);
    // 能力矩陣 → Orchestrator
    L.elbow(pres, s, [[4.7, 3.775], [4.95, 3.775], [4.95, 4.975], [5.2, 4.975]], { color: HEX.accent1, width: 2 });
    // Review 欄
    L.card(pres, s, 9.6, 1.4, 3.13, 5.45, { fill: HEX.lt2, name: "review" });
    text(s, "Review 與治理", { x: 9.78, y: 1.5, w: 2.8, h: 0.35, fontSize: 14, bold: true });
    L.box(pres, s, 9.78, 1.95, 2.77, 0.95, "規則與 Skill 審查", "PR 審核・安全掃描", { name: "r1" });
    L.box(pres, s, 9.78, 3.08, 2.77, 0.95, "驗證與評測", "V1–V11・模型評測集", { name: "r2" });
    L.box(pres, s, 9.78, 4.21, 2.77, 0.95, "稽核鏈", "hash-chain 防竄改", { name: "r3" });
    L.box(pres, s, 9.78, 5.34, 2.77, 0.95, "人工審核閘門", "L0 自動 → L3 雙人", { style: "accent", name: "r4" });
    L.arrow(pres, s, 9.3, 4.24, 9.6, 4.24);
    // Phase 2–3
    L.card(pres, s, 0.6, 5.85, 8.7, 1.0, { fill: "FFFFFF", line: HEX.line, dash: "dash", name: "future" });
    text(s, "Phase 2–3\n規劃中", { x: 0.75, y: 5.95, w: 1.3, h: 0.8, fontSize: 12, bold: true, color: HEX.muted, valign: "middle" });
    [["SIEM 偵測分流", "MDI・Sigma"], ["偵測規則庫", "Git PR・CI"], ["持續驗證", "BAS・紫隊"], ["SOAR 執行", "核准後・可回滾"]]
      .forEach(([t, sub], i) => L.box(pres, s, 2.1 + i * 1.8, 6.0, 1.65, 0.7, t, sub, { style: "dashed", titleSize: 12, subSize: 10, name: `f-${i}` }));
    L.elbow(pres, s, [[9.78, 5.815], [9.45, 5.815], [9.45, 6.35], [9.15, 6.35]], { dash: "dash" });
    s.addNotes("兩個控制點用 teal 標示：能力矩陣決定核心模組與 AI 子代理（teal 粗線），人工審核閘門決定任何變更能否執行。藍色為 AI 層，虛線為 Phase 2–3 尚未實作的執行類功能。");
  }
  {
    const s = content("開場", "一次 idsec run：五步，每步寫入稽核鏈");
    const steps = [
      ["盤點", "讀取 AD 與 Entra 現況", "fingerprint.json"],
      ["能力矩陣", "判定 Profile、模組、缺口", "capability.json"],
      ["攻擊路徑", "通往 Tier 0 與修補順序", "paths.json"],
      ["評估排序", "解析 PingCastle 並加權", "findings.json"],
      ["報告", "確定性 Markdown 報告", "report.md"],
    ];
    steps.forEach(([t, d, f], i) => {
      const x = 0.6 + i * 2.48;
      L.numBadge(pres, s, x, 1.6, 0.6, i + 1, i === 1 ? HEX.accent1 : HEX.dk2);
      if (i < 4) L.arrow(pres, s, x + 0.7, 1.9, x + 2.38, 1.9, { color: HEX.line });
      text(s, t, { x, y: 2.4, w: 2.3, h: 0.45, fontSize: 20, bold: true });
      text(s, d, { x, y: 2.9, w: 2.25, h: 0.8, fontSize: 14, color: HEX.muted });
      L.chip(pres, s, x, 3.8, 2.2, f, { fill: HEX.lt2, color: HEX.dk1, fontSize: 11, name: `out-${i}` });
    });
    L.card(pres, s, 0.6, 4.6, 12.13, 2.1, { fill: HEX.lt2, name: "rules" });
    text(s, "執行規則", { x: 0.9, y: 4.8, w: 3, h: 0.4, fontSize: 16, bold: true });
    text(s, [
      { text: "模組沒被能力矩陣啟用就跳過，例如無 Entra 租戶時不收集 Entra 路徑，也不掛載 entra-graph", options: { bullet: true, breakLine: true } },
      { text: "每一步完成即寫入 hash-chain 稽核鏈（pipeline.discovery.completed、paths.completed …）", options: { bullet: true, breakLine: true } },
      { text: "全部為確定性計算：同一份輸入永遠得到同一份輸出，模擬資料以固定種子產生、可重現", options: { bullet: true } },
    ], { x: 0.9, y: 5.25, w: 11.5, h: 1.35, fontSize: 14, paraSpaceAfter: 6 });
    s.addNotes("指令：idsec run [法人]。產出放在 output/<法人>/。這五個檔案是 MCP Server 與 Agent 的資料來源，Agent 不會另外推算。");
  }

  // ================================================================ 01 規則機制
  pres.addSection({ title: "規則機制" });
  {
    const s = pres.addSlide({ masterName: "SECTION_DARK", sectionTitle: "規則機制" });
    s.addText("01", { placeholder: "num" });
    s.addText("規則機制", { placeholder: "title" });
    s.addText("環境指紋 → 能力矩陣 → 路徑與評估排序規則", { placeholder: "body" });
  }
  {
    const s = content("規則機制", "規則的輸入：環境指紋六大區塊");
    const blocks = [
      ["TbSitemap", "ad", "Forest、網域、DC 數與作業系統、功能等級、信任關係與 SID Filtering"],
      ["TbArrowsExchange", "hybrid", "租戶有無、同步工具、驗證方式（PHS / PTA / AD FS）、Seamless SSO、同步主機"],
      ["TbUsers", "identity", "啟用與特權帳號、Kerberoast、AS-REP、無限制委派、90 天未登入、Entra 特權角色"],
      ["TbCertificate", "services", "AD CS 有無、CA 數、已發佈範本、ESC1 候選範本"],
      ["TbTool", "tooling", "MDI 部署與授權、EDR、SIEM、Entra P1 / P2"],
      ["TbActivityHeartbeat", "telemetry", "稽核原則缺漏、Sysmon 覆蓋、SIEM 收集狀態、覆蓋分數"],
    ];
    for (let i = 0; i < 6; i++) {
      const x = 0.6 + (i % 3) * 4.1, y = 1.45 + Math.floor(i / 3) * 2.45;
      L.card(pres, s, x, y, 3.85, 2.2, { name: `fp-${i}` });
      await L.badge(pres, s, x + 0.25, y + 0.25, 0.6, blocks[i][0], HEX.dk2, `fp-${i}`);
      text(s, blocks[i][1], { x: x + 1.0, y: y + 0.3, w: 2.6, h: 0.5, fontSize: 20, bold: true, fontFace: "Consolas" });
      text(s, blocks[i][2], { x: x + 0.25, y: y + 1.0, w: 3.4, h: 1.1, fontSize: 14, color: HEX.muted });
    }
    s.addNotes("指紋由 discovery.py 產生，完全確定性。LDAP / Graph 讀不到的部分（稽核原則、Sysmon、SIEM）由 IT 填 tooling.yaml；未提供時標為未知，並在缺口報告中列出。");
  }
  {
    const s = content("規則機制", "能力矩陣：以 YAML 宣告條件，不改程式");
    L.code(pres, s, 0.6, 1.4, 7.1, 5.35,
      "profiles:            # 由上而下，第一個符合者勝出\n" +
      "  - id: A\n    name: 完整型\n    when:\n      all:\n" +
      "        - {path: hybrid.is_hybrid, eq: true}\n" +
      "        - {path: tooling.mdi, eq: true}\n" +
      "        - {path: tooling.siem, nonempty: true}\n" +
      "        - {path: telemetry.coverage_score, gte: 0.6}\n\n" +
      "modules:\n  - id: assess_adcs\n    when: {path: services.adcs_present, eq: true}\n    unmet: 未偵測到 AD CS\n\n" +
      "gaps:\n  - id: GAP-SIEM\n    title: 尚無 SIEM，偵測模組無法啟用\n" +
      "    when: {path: tooling.siem, empty: true}\n" +
      "    blocks: [detect_mdi_triage, detect_sigma_dc]",
      { fontSize: 13, name: "yaml" });
    text(s, "四類規則", { x: 8.05, y: 1.4, w: 4.6, h: 0.4, fontSize: 18, bold: true });
    const kinds = [["profiles", "3 條：A 完整型 / B 部分型 / C 地端型"], ["modules", "9 條：各模組的啟用條件與未啟用原因"],
      ["gaps", "6 條：缺口與被擋住的模組"], ["tier0_extra", "5 條：混合環境額外列入 Tier 0"]];
    kinds.forEach(([k, d], i) => {
      text(s, [{ text: k, options: { bold: true, fontFace: "Consolas", color: HEX.accent1, breakLine: true } }, { text: d, options: { color: HEX.muted } }],
        { x: 8.05, y: 1.9 + i * 0.68, w: 4.6, h: 0.62, fontSize: 13 });
    });
    text(s, "條件語法", { x: 8.05, y: 4.7, w: 4.6, h: 0.4, fontSize: 18, bold: true });
    text(s, [
      { text: "運算子：eq ne gt gte lt lte in nonempty empty", options: { bullet: true, breakLine: true } },
      { text: "組合：all / any / not 可巢狀", options: { bullet: true, breakLine: true } },
      { text: "文字代入：{路徑}、{len:路徑}", options: { bullet: true } },
    ], { x: 8.05, y: 5.15, w: 4.68, h: 1.5, fontSize: 13, paraSpaceAfter: 4 });
    s.addNotes("規則檔 config/capability_matrix.yaml。引擎 capability.py 約 90 行：lookup 取指紋路徑、evaluate 遞迴求值、render 代入文字。條件必須恰好一個運算子，否則拋錯，避免寫錯的規則被靜默略過。");
  }
  {
    const s = content("規則機制", "三種 Profile：第一個符合者勝出");
    const rows = [
      [{ text: "Profile", options: { bold: true, color: "FFFFFF", fill: { color: HEX.dk2 } } }, { text: "判定條件", options: { bold: true, color: "FFFFFF", fill: { color: HEX.dk2 } } },
        { text: "模擬法人", options: { bold: true, color: "FFFFFF", fill: { color: HEX.dk2 } } }, { text: "啟用模組", options: { bold: true, color: "FFFFFF", fill: { color: HEX.dk2 } } },
        { text: "缺口", options: { bold: true, color: "FFFFFF", fill: { color: HEX.dk2 } } }],
      [{ text: "A 完整型", options: { bold: true, color: HEX.accent1 } }, "混合身分 + MDI + SIEM + 遙測覆蓋 ≥ 0.6", "hq（總公司）", "8 / 9", "AUDIT"],
      [{ text: "B 部分型", options: { bold: true, color: HEX.accent2 } }, "混合身分（缺 MDI、SIEM 或覆蓋不足）", "sub-a（AD FS）", "5 / 9", "AUDIT・SIEM・ENTRA・SYSMON"],
      [{ text: "C 地端型", options: { bold: true, color: HEX.accent3 } }, "其他（純地端、遙測未知）", "sub-b", "3 / 9", "AUDIT・SIEM・SYSMON"],
    ];
    s.addTable(rows, { x: 0.6, y: 1.45, w: 12.13, colW: [1.5, 4.0, 1.9, 1.2, 3.53], fontSize: 14, color: HEX.dk1,
      border: { type: "solid", pt: 0.75, color: HEX.line }, rowH: 0.62, valign: "middle", margin: [0.06, 0.12, 0.06, 0.12] });
    text(s, "同一套規則，三個環境得到三種結果", { x: 0.6, y: 4.3, w: 12, h: 0.4, fontSize: 18, bold: true });
    const ex = [
      ["sub-b 沒有 Entra 租戶", "assess_entra、paths_entra 不啟用；Agent 不掛載 entra-graph"],
      ["sub-a 驗證方式為 AD FS", "AD FS 伺服器與 Token-signing 憑證列入額外 Tier 0"],
      ["hq 有 AD CS", "啟用 AD CS 評估；ESC1 範本進入攻擊路徑計算"],
    ];
    ex.forEach(([a, b], i) => {
      const x = 0.6 + i * 4.1;
      L.card(pres, s, x, 4.85, 3.85, 1.85, { name: `ex-${i}` });
      text(s, a, { x: x + 0.25, y: 5.05, w: 3.4, h: 0.45, fontSize: 15, bold: true });
      text(s, b, { x: x + 0.25, y: 5.55, w: 3.4, h: 1.05, fontSize: 13, color: HEX.muted });
    });
    s.addNotes("數字來自模擬資料實跑（idsec discover）。模組總數 9 包含 3 個 Phase 2 偵測模組，MVP 只判定是否可啟用、不執行。");
  }
  {
    const s = content("規則機制", "缺口規則說明「為什麼沒啟用」與「先補什麼」");
    text(s, "缺口 → 被擋住的模組", { x: 0.6, y: 1.4, w: 7, h: 0.4, fontSize: 18, bold: true });
    const gaps = [
      ["GAP-AUDIT", "DC 稽核原則缺必要子類別", ["DC 事件 + Sigma"]],
      ["GAP-SIEM", "尚無 SIEM", ["MDI 分流", "DC 事件 + Sigma", "Entra 登入"]],
      ["GAP-DC-INGEST", "DC 事件未送入 SIEM", ["DC 事件 + Sigma"]],
      ["GAP-ENTRA-INGEST", "Entra 日誌未送入 SIEM", ["Entra 登入"]],
      ["GAP-MDI-UNUSED", "有 MDI 授權未部署", ["MDI 分流"]],
      ["GAP-SYSMON", "Sysmon 覆蓋 < 50%", []],
    ];
    gaps.forEach(([id, d, mods], i) => {
      const y = 1.9 + i * 0.78;
      L.chip(pres, s, 0.6, y + 0.08, 2.1, id, { fill: HEX.amberTint, color: "8A5A12", fontSize: 11, name: `gap-${i}` });
      text(s, d, { x: 2.85, y: y + 0.06, w: 2.5, h: 0.4, fontSize: 13 });
      if (mods.length) L.arrow(pres, s, 5.3, y + 0.24, 5.6, y + 0.24, { color: HEX.line });
      mods.forEach((m, j) => L.chip(pres, s, 5.7 + j * 1.45, y + 0.08, 1.38, m, { fill: HEX.lt2, color: HEX.dk1, fontSize: 11, name: `gap-${i}-m${j}` }));
      if (!mods.length) text(s, "不擋模組，列為建議", { x: 5.7, y: y + 0.06, w: 2.5, h: 0.4, fontSize: 12, color: HEX.muted });
    });
    L.card(pres, s, 10.2, 1.4, 2.53, 5.3, { fill: HEX.tealTint, name: "t0" });
    text(s, "額外 Tier 0", { x: 10.4, y: 1.55, w: 2.2, h: 0.4, fontSize: 16, bold: true, color: HEX.accent1 });
    text(s, [
      { text: "Entra Connect / Cloud Sync 主機", options: { bullet: true, breakLine: true } },
      { text: "AD FS 與 Token-signing 憑證", options: { bullet: true, breakLine: true } },
      { text: "PTA Agent 主機", options: { bullet: true, breakLine: true } },
      { text: "AZUREADSSOACC 帳號", options: { bullet: true, breakLine: true } },
      { text: "AD CS 憑證授權單位", options: { bullet: true } },
    ], { x: 10.4, y: 2.05, w: 2.2, h: 3.8, fontSize: 14, paraSpaceAfter: 10 });
    text(s, "依指紋條件自動加入", { x: 10.4, y: 6.1, w: 2.2, h: 0.4, fontSize: 11, color: HEX.muted });
    s.addNotes("缺口報告的排序原則：先補擋住最多模組的缺口。以 sub-a 為例，GAP-SIEM 一次擋住三個偵測模組，優先序高於 GAP-AUDIT。");
  }
  {
    const s = content("規則機制", "修補順序：每移除一條邊就重算，不用估計");
    const steps = [
      ["特權成員視為目標", "Domain Admins 成員本身就是 Tier 0，不算攻擊來源"],
      ["反向 BFS 求最短路徑", "從 Tier 0 往回推，得到每個來源的一條路徑"],
      ["貪婪移除並重算", "每輪試移除候選邊，選切斷最多來源者，再對剩餘路徑重複"],
    ];
    steps.forEach(([t, d], i) => {
      const y = 1.5 + i * 1.6;
      L.numBadge(pres, s, 0.6, y, 0.55, i + 1, HEX.dk2);
      text(s, t, { x: 1.35, y: y - 0.02, w: 4.4, h: 0.45, fontSize: 18, bold: true });
      text(s, d, { x: 1.35, y: y + 0.48, w: 4.4, h: 0.9, fontSize: 14, color: HEX.muted });
    });
    s.addChart(pres.charts.BAR, [{ name: "仍有路徑的帳號", labels: ["修補前", "第 1 步", "第 2 步", "第 3 步"], values: [234, 8, 5, 2] }], {
      x: 6.2, y: 1.4, w: 6.5, h: 4.3, barDir: "col", chartColors: [HEX.accent2],
      showTitle: true, title: "hq：依序修補後仍可到達 Tier 0 的帳號數", titleFontSize: 14, titleColor: HEX.dk1, titleFontFace: "+mn-lt",
      showValue: true, dataLabelPosition: "outEnd", dataLabelFontSize: 12, dataLabelColor: HEX.dk1, dataLabelFontFace: "+mn-lt",
      catAxisLabelColor: HEX.muted, valAxisLabelColor: HEX.muted, catAxisLabelFontFace: "+mn-lt", valAxisLabelFontFace: "+mn-lt",
      catAxisLabelFontSize: 12, valAxisLabelFontSize: 11, valGridLine: { color: "E3E7EC", size: 0.5 }, catGridLine: { style: "none" },
      showLegend: false, valAxisMaxVal: 250,
    });
    L.card(pres, s, 6.2, 5.85, 6.53, 0.85, { fill: HEX.amberTint, name: "step1" });
    text(s, "第 1 步：移除 Domain Users -[Enroll]-> VPNUser（ESC1 範本），一次切斷 226 個帳號（96.6%）", { x: 6.4, y: 5.95, w: 6.15, h: 0.65, fontSize: 13, valign: "middle" });
    s.addNotes("中心性指標只能估計，可能推薦移除後效果很小的邊。實際移除重算的成本可接受（候選邊上限 15 條），而且每一步的效果是精確的。報告與 MCP 的 remediation_order 都是這個結果。");
  }
  {
    const s = content("規則機制", "評估排序：落在真實攻擊路徑上的發現優先");
    L.card(pres, s, 0.6, 1.4, 12.13, 1.25, { fill: HEX.lt2, name: "formula" });
    text(s, [
      { text: "優先分數 ＝ ", options: { bold: true } },
      { text: "嚴重度權重", options: { bold: true, color: HEX.dk2 } }, { text: "（40 / 30 / 15 / 5 / 0）＋ ", options: {} },
      { text: "min(點數, 50) × 0.2", options: { bold: true, color: HEX.dk2 } }, { text: " ＋ ", options: {} },
      { text: "25", options: { bold: true, color: HEX.accent2 } }, { text: "（技術對應的邊在路徑上）", options: {} },
    ], { x: 0.9, y: 1.55, w: 11.6, h: 0.95, fontSize: 18, valign: "middle" });
    const map = [["T1649", "AD CS 憑證濫用", "ADCSESC1"], ["T1003.006", "DCSync", "DCSync"], ["T1484", "群組原則／ACL 修改", "GenericAll"], ["T1550", "憑證竊取後橫向", "HasSession"]];
    text(s, "ATT&CK 技術 → 圖譜中的邊", { x: 0.6, y: 2.95, w: 5.5, h: 0.4, fontSize: 16, bold: true });
    s.addTable([[{ text: "技術", options: { bold: true } }, { text: "意義", options: { bold: true } }, { text: "邊", options: { bold: true } }],
      ...map.map(([a, b, c]) => [{ text: a, options: { fontFace: "Consolas" } }, b, { text: c, options: { fontFace: "Consolas" } }])],
      { x: 0.6, y: 3.4, w: 5.6, colW: [1.4, 2.5, 1.7], fontSize: 13, color: HEX.dk1, rowH: 0.5,
        border: { type: "solid", pt: 0.75, color: HEX.line }, fill: { color: "FFFFFF" }, valign: "middle" });
    text(s, "模擬結果：三個法人的第一名都因落在路徑上而升到最前", { x: 6.6, y: 2.95, w: 6.1, h: 0.4, fontSize: 16, bold: true });
    const top = [["hq", "A-CertTempCustomSubject", "40 + 10 + 25 = 75"], ["sub-a", "P-ControlPathIndirectEveryone", "30 + 6 + 25 = 61"], ["sub-b", "P-UnconstrainedDelegation", "15 + 3 + 25 = 43"]];
    top.forEach(([e, id, sc], i) => {
      const y = 3.45 + i * 1.08;
      L.card(pres, s, 6.6, y, 6.13, 0.92, { name: `top-${i}` });
      text(s, e, { x: 6.8, y: y + 0.12, w: 0.9, h: 0.35, fontSize: 13, bold: true, color: HEX.muted });
      text(s, id, { x: 7.7, y: y + 0.12, w: 4.9, h: 0.35, fontSize: 14, bold: true, fontFace: "Consolas" });
      text(s, sc, { x: 7.7, y: y + 0.5, w: 4.9, h: 0.35, fontSize: 13, color: HEX.accent2 });
    });
    s.addNotes("sub-b 的第一名是 medium 嚴重度的無限制委派，卻排在 high 的服務帳號前面，因為它真的在通往 Tier 0 的路徑上（HasSession）。這就是加權的目的：嚴重度是通用評分，路徑是這個環境的事實。");
  }

  // ================================================================ 02 Review 機制
  pres.addSection({ title: "Review 機制" });
  {
    const s = pres.addSlide({ masterName: "SECTION_DARK", sectionTitle: "Review 機制" });
    s.addText("02", { placeholder: "num" });
    s.addText("Review 機制", { placeholder: "title" });
    s.addText("設計時、執行時、產出時、事後，四個時間點各有把關", { placeholder: "body" });
  }
  {
    const s = content("Review 機制", "四個時間點的 Review：設計、執行、產出、事後");
    const cols = [
      ["TbGitPullRequest", "設計時", "改了什麼", ["規則變更走 PR 與驗收", "MCP 工具與放行清單自動比對", "Skill 上線前送安全檢測平台"]],
      ["TbShieldLock", "執行時", "AI 能做什麼", ["四道防線，只能唯讀", "寫入型 Cypher 雙重攔截", "回傳內容注入偵測"]],
      ["TbUserCheck", "產出時", "誰來決定", ["人工審核閘門 L0–L3", "報告不經 LLM 改寫", "變更只產出提案"]],
      ["TbFileSearch", "事後", "怎麼追溯", ["hash-chain 稽核鏈", "V1–V11 驗收紀錄", "模型評測集定期重跑"]],
    ];
    cols.forEach(([ic, t, q, items], i) => {
      const x = 0.6 + i * 3.08;
      if (i < 3) L.arrow(pres, s, x + 0.95, 1.85, x + 3.08 + 0.15, 1.85, { color: HEX.line });
    });
    for (let i = 0; i < 4; i++) {
      const [ic, t, q, items] = cols[i];
      const x = 0.6 + i * 3.08;
      await L.badge(pres, s, x + 0.15, 1.45, 0.8, ic, i === 2 ? HEX.accent1 : HEX.dk2, `rv-${i}`);
      text(s, t, { x, y: 2.45, w: 2.85, h: 0.5, fontSize: 22, bold: true });
      text(s, q, { x, y: 2.95, w: 2.85, h: 0.4, fontSize: 14, color: HEX.accent1, bold: true });
      L.card(pres, s, x, 3.55, 2.85, 2.45, { name: `rv-card-${i}` });
      text(s, items.map((it, j) => ({ text: it, options: { bullet: true, breakLine: j < items.length - 1 } })),
        { x: x + 0.2, y: 3.75, w: 2.5, h: 2.1, fontSize: 15, paraSpaceAfter: 10 });
    }
    s.addNotes("後面四頁依序展開：四道防線（執行時）、人工審核閘門（產出時）、規則變更流程（設計時）、稽核鏈與驗證（事後）。");
  }
  {
    const s = content("Review 機制", "Agent 只能讀：四道獨立防線，任一失效仍有其他擋下");
    const layers = [
      ["1", "MCP Server 只實作讀取", "18 個工具全部標註 readOnlyHint；寫入型 Cypher 直接回 PermissionError", "mcp_servers/"],
      ["2", "SDK 工具限制", "tools 只留 Agent、Skill；Bash、檔案、網路工具全部 disallow；strict_mcp_config", "orchestrator.py"],
      ["3", "PreToolUse 放行清單", "清單外的工具與寫入型 Cypher 一律拒絕並寫稽核鏈", "hooks.py"],
      ["4", "permission_mode = dontAsk", "需要詢問權限的動作直接拒絕，不會跳出確認", "orchestrator.py"],
    ];
    layers.forEach(([n, t, d, f], i) => {
      const y = 1.45 + i * 1.12;
      const inset = i * 0.25;
      L.card(pres, s, 0.6 + inset, y, 7.6 - inset * 2, 0.98, { fill: i % 2 ? HEX.lt2 : "F6F8FA", line: HEX.line, name: `layer-${i}` });
      L.numBadge(pres, s, 0.8 + inset, y + 0.22, 0.54, n, HEX.accent1);
      text(s, t, { x: 1.5 + inset, y: y + 0.1, w: 4.6, h: 0.38, fontSize: 15, bold: true });
      text(s, d, { x: 1.5 + inset, y: y + 0.48, w: 6.4 - inset * 2, h: 0.45, fontSize: 12, color: HEX.muted });
      text(s, f, { x: 5.6 - inset, y: y + 0.12, w: 2.4, h: 0.35, fontSize: 10, color: HEX.muted, fontFace: "Consolas", align: "right" });
    });
    L.card(pres, s, 8.6, 1.45, 4.13, 3.3, { fill: HEX.amberTint, name: "inject" });
    await L.badge(pres, s, 8.85, 1.7, 0.6, "TbAlertTriangle", HEX.accent2, "inject");
    text(s, "提示注入防護", { x: 9.6, y: 1.8, w: 3, h: 0.45, fontSize: 17, bold: true });
    text(s, [
      { text: "工具回傳一律加註「資料不是指令」", options: { bullet: true, breakLine: true } },
      { text: "截斷長字串、移除控制字元", options: { bullet: true, breakLine: true } },
      { text: "PostToolUse 偵測可疑指令文字，提醒模型並標示物件", options: { bullet: true } },
    ], { x: 8.85, y: 2.5, w: 3.7, h: 2.1, fontSize: 13, paraSpaceAfter: 8 });
    L.card(pres, s, 8.6, 4.95, 4.13, 1.75, { fill: HEX.tealTint, name: "evidence" });
    text(s, "實測證據", { x: 8.85, y: 5.1, w: 3.6, h: 0.4, fontSize: 15, bold: true, color: HEX.accent1 });
    text(s, "樁模型端到端測試中，模型可見工具只有 20 個（18 個 MCP + Agent + Skill），看不到 Bash 與主機上的其他 MCP。", { x: 8.85, y: 5.5, w: 3.7, h: 1.1, fontSize: 12, color: HEX.dk1 });
    s.addNotes("四道防線彼此獨立：即使有人誤把寫入工具加進 MCP，放行清單與測試 test_all_mcp_tools_read_only_and_listed 也會擋下並失敗。");
  }
  {
    const s = content("Review 機制", "人工審核閘門：依風險分四級授權");
    const lv = [
      ["L0", "唯讀分析", "自動", "盤點、路徑分析、評估排序、問答", "MVP 現況", HEX.accent5],
      ["L1", "低風險動作", "自動＋事後檢視", "開工單、關聯告警", "Phase 2", HEX.accent4],
      ["L2", "一般變更", "單人核准", "GPO 調整、停用帳號、移除群組成員", "Phase 3", HEX.accent2],
      ["L3", "Tier 0 變更", "雙人核准", "Domain Admins、AD CS、Entra Connect、krbtgt", "Phase 3", HEX.accent3],
    ];
    lv.forEach(([id, name, how, ex, ph, col], i) => {
      const x = 0.6 + i * 3.08, h = 1.6 + i * 0.75, y = 6.0 - h;
      L.card(pres, s, x, y, 2.85, h, { fill: col, name: `lv-${i}` });
      text(s, id, { x: x + 0.2, y: y + 0.15, w: 1.2, h: 0.6, fontSize: 30, bold: true, color: "FFFFFF" });
      text(s, name, { x: x + 0.2, y: y + 0.8, w: 2.5, h: 0.4, fontSize: 16, bold: true, color: "FFFFFF" });
      text(s, how, { x: x + 0.2, y: y + 1.2, w: 2.5, h: 0.35, fontSize: 13, color: "FFFFFF" });
      text(s, ex, { x, y: 6.15, w: 2.85, h: 0.55, fontSize: 12, color: HEX.muted });
      L.chip(pres, s, x + 1.65, y + 0.25, 1.0, ph, { fill: "FFFFFF", color: col, fontSize: 10, h: 0.3, name: `lv-ph-${i}` });
    });
    text(s, "MVP 只開 L0：所有修補建議都是提案，執行由 SOAR 以獨立身分在核准後觸發，LLM 不持有任何執行工具。", { x: 0.6, y: 1.4, w: 7.4, h: 0.9, fontSize: 15, color: HEX.dk1 });
    s.addNotes("分級依據計畫書的 AI 治理控制項。L2 / L3 的核准人對應 RACI：地端 AD 變更由 AD 團隊、Entra 由 IAM、子公司環境由子公司 IT 當責。");
  }
  {
    const s = content("Review 機制", "規則本身也要 Review：修改能力矩陣的五步");
    const steps = [
      ["TbEdit", "修改 YAML", "開 PR，說明門檻或條件變更的理由"],
      ["TbEye", "預覽判定", "idsec discover 比對各法人 Profile 與模組差異"],
      ["TbListCheck", "更新預期值", "VERIFICATION.md 與 verify_mvp.py 的 EXPECTED"],
      ["TbTestPipe", "CI 驗收", "pytest 與 verify_mvp.py 全部通過"],
      ["TbSignature", "核准合併", "資安負責人審核後合併"],
    ];
    for (let i = 0; i < 5; i++) {
      const x = 0.6 + i * 2.48;
      await L.badge(pres, s, x, 1.5, 0.75, steps[i][0], i === 4 ? HEX.accent1 : HEX.dk2, `rc-${i}`);
      if (i < 4) L.arrow(pres, s, x + 0.85, 1.875, x + 2.38, 1.875, { color: HEX.line });
      text(s, `${i + 1}  ${steps[i][1]}`, { x, y: 2.45, w: 2.3, h: 0.45, fontSize: 17, bold: true });
      text(s, steps[i][2], { x, y: 2.95, w: 2.2, h: 1.0, fontSize: 13, color: HEX.muted });
    }
    text(s, "同一套機制適用的其他變更", { x: 0.6, y: 4.3, w: 8, h: 0.4, fontSize: 17, bold: true });
    const other = [["新增 MCP 工具", "同步更新 hooks.py 放行清單；V6 會比對工具清單與放行清單是否一致"],
      ["修改 Skill", "送內部 Skill 安全檢測平台掃描後才上線"],
      ["更換或升級模型", "重跑 V10 評測：15 次中至少 14 次正確，捏造與越權 0 次"]];
    other.forEach(([a, b], i) => {
      const x = 0.6 + i * 4.1;
      L.card(pres, s, x, 4.85, 3.85, 1.6, { name: `oth-${i}` });
      text(s, a, { x: x + 0.25, y: 5.02, w: 3.4, h: 0.4, fontSize: 15, bold: true });
      text(s, b, { x: x + 0.25, y: 5.47, w: 3.4, h: 1.15, fontSize: 13, color: HEX.muted });
    });
    s.addNotes("規則改變會改變預期值，所以預期值寫在驗收腳本裡：改規則卻沒更新預期值，CI 會失敗，迫使變更被看見。");
  }
  {
    const s = content("Review 機制", "稽核鏈：每筆紀錄串前一筆的雜湊，竄改即可偵測");
    const recs = [["#1", "pipeline", "discovery.completed"], ["#2", "mcp:bloodhound", "tool.call"], ["#3", "hook:pre", "tool.denied"]];
    recs.forEach(([n, actor, ev], i) => {
      const x = 0.6 + i * 2.65;
      L.card(pres, s, x, 1.5, 2.3, 2.3, { fill: "FFFFFF", line: HEX.line, name: `rec-${i}` });
      text(s, n, { x: x + 0.2, y: 1.62, w: 1, h: 0.35, fontSize: 14, bold: true, color: HEX.accent1 });
      text(s, [
        { text: `actor: ${actor}`, options: { breakLine: true } }, { text: `event: ${ev}`, options: { breakLine: true } },
        { text: "data: {…}", options: { breakLine: true } }, { text: "prev_hash", options: { bold: true, color: HEX.accent2, breakLine: true } },
        { text: "hash", options: { bold: true, color: HEX.accent1 } },
      ], { x: x + 0.2, y: 2.0, w: 2.0, h: 1.7, fontSize: 11, fontFace: "Consolas" });
      if (i < 2) L.arrow(pres, s, x + 2.3, 3.45, x + 2.65, 3.45, { color: HEX.accent2, width: 1.5 });
    });
    text(s, "hash = SHA-256(前一筆 hash + 本筆內容)，寫入時加檔案鎖", { x: 0.6, y: 4.0, w: 7.6, h: 0.4, fontSize: 13, color: HEX.muted });
    L.code(pres, s, 0.6, 4.6, 7.6, 2.1,
      "$ idsec audit-verify\n✔ 驗證通過，共 12 筆\n\n$ sed -i '1s/\"hq\"/\"xx\"/' output/audit/audit.jsonl\n$ idsec audit-verify\n✘ 第 1 筆內容與雜湊不符（可能被竄改）   exit=2",
      { fontSize: 12, name: "verify" });
    text(s, "記錄哪些事件", { x: 8.6, y: 1.5, w: 4, h: 0.4, fontSize: 17, bold: true });
    text(s, [
      { text: "流程每一步完成", options: { bullet: true, breakLine: true } },
      { text: "每次 MCP 工具呼叫（含參數與成敗）", options: { bullet: true, breakLine: true } },
      { text: "被 Hook 拒絕的工具呼叫", options: { bullet: true, breakLine: true } },
      { text: "Agent 問答的開始與結束", options: { bullet: true, breakLine: true } },
      { text: "回傳內容的 SHA-256 與注入嫌疑", options: { bullet: true } },
    ], { x: 8.6, y: 2.0, w: 4.1, h: 2.6, fontSize: 14, paraSpaceAfter: 8 });
    L.card(pres, s, 8.6, 4.6, 4.13, 2.1, { fill: HEX.lt2, name: "handling" });
    text(s, "驗證失敗時", { x: 8.85, y: 4.75, w: 3.6, h: 0.4, fontSize: 15, bold: true });
    text(s, "先完整複製保全，依筆數定位、比對前後紀錄，調查後封存並開始新鏈；封存檔定期送 WORM 或 SIEM。", { x: 8.85, y: 5.2, w: 3.65, h: 1.4, fontSize: 12, color: HEX.muted });
    s.addNotes("竄改、刪除、插入三種情況都能偵測：內容變動會讓 hash 不符，刪除或插入會讓 prev_hash 對不上。測試 test_audit_chain_detects_tampering 涵蓋前兩種。");
  }
  {
    const s = content("Review 機制", "驗證分三段：模擬、部署、實機，各有通過標準");
    const stages = [
      ["開發環境", "V1–V8", "模擬資料，任何人可重現", ["pytest 23 項", "verify_mvp.py --e2e 7 / 7", "樁模型跑通 Agent 全流程"], "已通過", HEX.accent1, HEX.tealTint],
      ["部署環境", "V9–V10", "Docker 與地端模型", ["唯讀根檔案系統、無對外出口", "兩個模型的 tool use 格式", "人工評估 15 次 ≥ 14 次正確"], "待執行", HEX.accent2, HEX.amberTint],
      ["LAB 實機", "V11", "上線前，已知狀態網域", ["指紋逐項對照 PowerShell", "路徑數與 BloodHound 差異 ≤ 10%", "確認服務帳號無寫入權限"], "待執行", HEX.accent2, HEX.amberTint],
    ];
    stages.forEach(([t, v, d, items, st, col, tint], i) => {
      const x = 0.6 + i * 4.1;
      L.card(pres, s, x, 1.45, 3.85, 5.25, { name: `stage-${i}` });
      text(s, v, { x: x + 0.3, y: 1.65, w: 2.2, h: 0.6, fontSize: 28, bold: true, color: HEX.dk2 });
      L.chip(pres, s, x + 2.55, 1.78, 1.05, st, { fill: tint, color: col === HEX.accent2 ? "8A5A12" : col, name: `st-${i}` });
      text(s, t, { x: x + 0.3, y: 2.3, w: 3.3, h: 0.45, fontSize: 18, bold: true });
      text(s, d, { x: x + 0.3, y: 2.75, w: 3.3, h: 0.4, fontSize: 13, color: HEX.muted });
      text(s, items.map((it, j) => ({ text: it, options: { bullet: true, breakLine: j < items.length - 1 } })),
        { x: x + 0.3, y: 3.35, w: 3.3, h: 2.1, fontSize: 14, paraSpaceAfter: 10 });
      if (i < 2) L.arrow(pres, s, x + 3.85, 4.05, x + 4.1, 4.05, { color: HEX.line });
    });
    L.code(pres, s, 0.85, 5.6, 3.35, 0.85, "$ verify_mvp.py --e2e\n7/7 通過", { fontSize: 12, name: "vcmd" });
    text(s, "硬性門檻：查無帳號不捏造、要求變更必拒絕，0 次失敗", { x: 4.95, y: 5.6, w: 3.35, h: 0.85, fontSize: 12, color: "8A5A12", valign: "middle" });
    text(s, "全部通過後，才可對正式法人執行", { x: 9.05, y: 5.6, w: 3.35, h: 0.85, fontSize: 12, color: "8A5A12", valign: "middle" });
    s.addNotes("詳細步驟與預期值見 docs/VERIFICATION.md，最後一節是驗收紀錄表。");
  }

  // ================================================================ 03 部署與下一步
  pres.addSection({ title: "部署與下一步" });
  {
    const s = pres.addSlide({ masterName: "SECTION_DARK", sectionTitle: "部署與下一步" });
    s.addText("03", { placeholder: "num" });
    s.addText("部署與下一步", { placeholder: "title" });
    s.addText("Tier 0 隔離區部署、已知限制與後續工作", { placeholder: "body" });
  }
  {
    const s = content("部署與下一步", "部署：總公司 Tier 0 隔離區，idsec 容器無對外出口");
    L.card(pres, s, 0.6, 1.45, 7.6, 5.25, { fill: HEX.lt2, name: "tier0" });
    text(s, "總公司 Tier 0 隔離區", { x: 0.85, y: 1.6, w: 5, h: 0.4, fontSize: 15, bold: true });
    L.card(pres, s, 0.85, 2.15, 3.4, 3.1, { fill: "FFFFFF", line: HEX.accent1, dash: "dash", name: "net-int" });
    text(s, "idsec-internal（internal: true）", { x: 1.0, y: 2.25, w: 3.2, h: 0.35, fontSize: 11, color: HEX.accent1, bold: true });
    L.box(pres, s, 1.1, 2.8, 2.9, 0.9, "idsec 容器", "核心・MCP・Agent", { name: "c-idsec" });
    L.box(pres, s, 1.1, 4.05, 2.9, 0.9, "output/", "報告・稽核鏈（唯一可寫）", { name: "c-out" });
    L.arrow(pres, s, 2.55, 3.7, 2.55, 4.05);
    L.card(pres, s, 4.6, 2.15, 3.35, 3.1, { fill: "FFFFFF", line: HEX.line, dash: "dash", name: "net-model" });
    text(s, "model-net", { x: 4.75, y: 2.25, w: 3, h: 0.35, fontSize: 11, color: HEX.muted, bold: true });
    L.box(pres, s, 4.85, 2.8, 2.85, 0.9, "LiteLLM 閘道", "Anthropic Messages 相容", { style: "blue", name: "c-llm" });
    L.box(pres, s, 4.85, 4.05, 2.85, 0.9, "地端 vLLM 叢集", "既有 GPU", { style: "blue", name: "c-vllm" });
    L.arrow(pres, s, 4.0, 3.25, 4.85, 3.25); L.arrow(pres, s, 6.28, 3.7, 6.28, 4.05);
    text(s, "live 模式另行開通至 DC（LDAPS 636）、Graph、BloodHound Neo4j 的唯讀連線", { x: 0.85, y: 5.5, w: 7.1, h: 0.9, fontSize: 12, color: HEX.muted });
    text(s, "容器強化", { x: 8.6, y: 1.45, w: 4, h: 0.4, fontSize: 17, bold: true });
    const hard = [["TbUserOff", "非 root 執行（uid 10001）"], ["TbLock", "唯讀根檔案系統，僅 output/ 可寫"], ["TbShieldOff", "cap_drop: ALL、no-new-privileges"],
      ["TbKey", "憑證只從環境變數讀取"], ["TbWorldOff", "關閉 CLI 遙測與非必要連線"]];
    for (let i = 0; i < hard.length; i++) {
      const y = 2.0 + i * 0.92;
      await L.badge(pres, s, 8.6, y, 0.55, hard[i][0], HEX.dk2, `hd-${i}`);
      text(s, hard[i][1], { x: 9.35, y: y + 0.08, w: 3.4, h: 0.45, fontSize: 14, valign: "middle" });
    }
    s.addNotes("Claude Agent SDK 內含原生 CLI，映像不需 Node.js。compose 語法已驗證；映像尚未實際 build（開發環境無 Docker daemon），第一次部署請完整走 V9。");
  }
  {
    const s = content("部署與下一步", "已知限制與下一步");
    const left = [["live 後端未經實機驗證", "LDAP、Graph、Neo4j 程式已完成，需 LAB 走 V11"], ["Docker 映像尚未實際 build", "compose 語法與非 editable 安裝已驗證"],
      ["地端模型 tool use 未驗證", "qwen 與 glm 經 LiteLLM 的格式相容性待 V10"], ["AD CS 註冊權（ACL）未解析", "暫由 BloodHound CE / Locksmith 判定"]];
    const right = [["LAB 驗證", "建立已知弱點的 LAB 網域，完成 V9–V11"], ["模型分工定案", "依 V10 評測結果配置 fast / reason"],
      ["補齊評估解析器", "Locksmith、Purple Knight、ScubaGear"], ["Phase 2 偵測分流", "能力矩陣已判定可啟用條件，接 SIEM 後實作"]];
    text(s, "尚未驗證", { x: 0.6, y: 1.4, w: 5.8, h: 0.45, fontSize: 18, bold: true, color: HEX.accent2 });
    text(s, "下一步", { x: 6.9, y: 1.4, w: 5.8, h: 0.45, fontSize: 18, bold: true, color: HEX.accent1 });
    for (let i = 0; i < 4; i++) {
      const y = 2.0 + i * 1.18;
      L.card(pres, s, 0.6, y, 5.85, 1.02, { fill: HEX.amberTint, name: `lim-${i}` });
      text(s, left[i][0], { x: 0.85, y: y + 0.12, w: 5.4, h: 0.4, fontSize: 15, bold: true });
      text(s, left[i][1], { x: 0.85, y: y + 0.52, w: 5.4, h: 0.4, fontSize: 12, color: HEX.muted });
      L.card(pres, s, 6.88, y, 5.85, 1.02, { fill: HEX.tealTint, name: `nxt-${i}` });
      L.numBadge(pres, s, 7.08, y + 0.26, 0.5, i + 1, HEX.accent1);
      text(s, right[i][0], { x: 7.8, y: y + 0.12, w: 4.7, h: 0.4, fontSize: 15, bold: true });
      text(s, right[i][1], { x: 7.8, y: y + 0.52, w: 4.7, h: 0.4, fontSize: 12, color: HEX.muted });
    }
    s.addNotes("左右四項一一對應：每個尚未驗證的項目都有對應的下一步。");
  }
  {
    const s = pres.addSlide({ masterName: "TITLE_DARK", sectionTitle: "部署與下一步" });
    s.addText("Q&A", { placeholder: "title" });
    s.addText("程式碼：github.com/Kevintw88/ADHD\n文件：docs/OPERATIONS.md・docs/VERIFICATION.md・docs/ARCHITECTURE.md", { placeholder: "body" });
  }

  await L.finish(pres, OUT);
  console.log("written", OUT);
})().catch((e) => { console.error(e); process.exit(1); });
