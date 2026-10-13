// 管理導向簡報：AD 與 Entra ID 混合環境 AI 資安防護（AI 效益與公司內部 AD 安全）
const pptxgen = require("pptxgenjs");
const L = require("./lib.js");
const { HEX } = L;

const OUT = process.argv[2] || "AD-Entra-AI資安防護-管理簡報.pptx";

(async () => {
  const pres = new pptxgen();
  L.setup(pres, "AD 與 Entra ID 混合環境 AI 資安防護｜管理簡報");
  pres.title = "AD 與 Entra ID 混合環境 AI 資安防護｜管理簡報";

  const content = (section, title) => {
    const s = pres.addSlide({ masterName: "CONTENT", sectionTitle: section });
    s.addText(title, { placeholder: "title" });
    return s;
  };
  const text = (s, t, o) => s.addText(t, { isTextBox: true, margin: 0, color: HEX.dk1, fontSize: 16, valign: "top", ...o });

  // ================================================================ 結論
  pres.addSection({ title: "結論" });
  {
    const s = pres.addSlide({ masterName: "TITLE_DARK", sectionTitle: "結論" });
    s.addText("用 AI 守住公司的身分核心", { placeholder: "title" });
    s.addText("AD 與 Entra ID 混合環境資安防護專案｜總公司與子公司", { placeholder: "body" });
  }
  {
    const s = content("結論", "結論：先看清楚，再修最關鍵的少數幾處");
    const pts = [
      ["TbTargetArrow", "AD 是攻擊者的首要目標", "取得網域控制權，就能控制全公司的帳號與系統"],
      ["TbRadar", "先偵測、後運行", "平台自動盤點每個法人，依現況啟用合適的防護，不一套方案硬套"],
      ["TbScissors", "少數修補，大幅降風險", "模擬驗證中，第一步修補即可切斷 57%–100% 的攻擊路徑"],
    ];
    for (let i = 0; i < 3; i++) {
      const y = 1.5 + i * 1.7;
      await L.badge(pres, s, 0.6, y, 0.85, pts[i][0], i === 0 ? HEX.accent2 : HEX.accent1, `pt-${i}`);
      text(s, pts[i][1], { x: 1.75, y: y + 0.02, w: 5.9, h: 0.5, fontSize: 22, bold: true });
      text(s, pts[i][2], { x: 1.75, y: y + 0.6, w: 5.9, h: 0.8, fontSize: 16, color: HEX.muted });
    }
    L.card(pres, s, 8.2, 1.5, 4.53, 5.2, { fill: HEX.dk2, name: "ask" });
    text(s, "需要的支持", { x: 8.55, y: 1.8, w: 3.9, h: 0.5, fontSize: 22, bold: true, color: "FFFFFF" });
    const asks = ["核定 AD 資料分級", "授權子公司導入", "以總公司為第一個試行點"];
    asks.forEach((a, i) => {
      L.numBadge(pres, s, 8.55, 2.65 + i * 1.05, 0.55, i + 1, HEX.accent6, HEX.dk2);
      text(s, a, { x: 9.3, y: 2.65 + i * 1.05, w: 3.2, h: 0.55, fontSize: 17, color: "FFFFFF", valign: "middle" });
    });
    text(s, "細節見最後一頁", { x: 8.55, y: 6.0, w: 3.9, h: 0.4, fontSize: 13, color: "AFC3D0" });
    s.addNotes("三句話：AD 是首要目標、我們依各法人現況分級處理、少數關鍵修補就能大幅降低風險。最後請管理層支持三件事。");
  }

  // ================================================================ 為什麼
  pres.addSection({ title: "為什麼" });
  {
    const s = content("為什麼", "AD 被攻破，等於全公司被攻破");
    // 中心輻射圖
    const cx = 3.75, cy = 4.1;
    const spokes = [["郵件", -1.9, -1.75], ["檔案伺服器", 1.9, -1.75], ["ERP", 2.3, 0], ["研發與 EDA 環境", 1.9, 1.75], ["VPN 遠端", -1.9, 1.75], ["雲端 M365", -2.3, 0]];
    for (const [t, dx, dy] of spokes) {
      L.arrow(pres, s, cx, cy, cx + dx * 0.72, cy + dy * 0.72, { color: HEX.line, head: false, width: 1.5 });
    }
    for (const [t, dx, dy] of spokes) {
      L.box(pres, s, cx + dx - 0.8, cy + dy - 0.3, 1.6, 0.6, t, null, { titleSize: 13, name: `sp-${t}` });
    }
    s.addShape(pres.shapes.OVAL, { x: cx - 0.95, y: cy - 0.95, w: 1.9, h: 1.9, fill: { color: HEX.dk2 }, line: { color: HEX.dk2 }, objectName: "hub" });
    text(s, "AD\nEntra ID", { x: cx - 0.95, y: cy - 0.95, w: 1.9, h: 1.9, fontSize: 18, bold: true, color: "FFFFFF", align: "center", valign: "middle" });
    text(s, "所有系統的登入與權限都由這裡發出", { x: 0.6, y: 6.3, w: 6.2, h: 0.4, fontSize: 13, color: HEX.muted, align: "center" });
    // 數據
    text(s, "78%+", { x: 7.6, y: 1.5, w: 5, h: 1.1, fontSize: 66, bold: true, color: HEX.accent2 });
    text(s, "人為操作的網路攻擊中，攻擊者成功入侵網域控制站", { x: 7.6, y: 2.65, w: 5.1, h: 0.8, fontSize: 17 });
    text(s, "35%+", { x: 7.6, y: 3.6, w: 5, h: 1.1, fontSize: 66, bold: true, color: HEX.accent3 });
    text(s, "的案例中，網域控制站是大規模散布勒索軟體的主要裝置", { x: 7.6, y: 4.75, w: 5.1, h: 0.8, fontSize: 17 });
    text(s, "資料來源：Microsoft Security Blog〈How cyberattackers exploit domain controllers using ransomware〉，2025-04-09", { x: 7.6, y: 6.0, w: 5.1, h: 0.65, fontSize: 11, color: HEX.muted,
      hyperlink: { url: "https://www.microsoft.com/en-us/security/blog/2025/04/09/how-cyberattackers-exploit-domain-controllers-using-ransomware" } });
    s.addNotes("數據為 Microsoft 公開資料。重點不是 AD 有沒有漏洞，而是攻擊者幾乎一定會走到 AD；拿下 AD 後，可以一次對全公司下手。");
  }
  {
    const s = content("為什麼", "我們的挑戰：成熟度不一、交界面多、人力有限");
    const cards = [
      ["TbBuildingFactory2", "總公司與子公司差異大", "有的法人已有 MDI 與 SIEM，有的連 DC 稽核日誌都沒開。同一套方案無法一體適用。"],
      ["TbArrowsSplit", "混合環境的交界面", "Entra Connect、AD FS 等同步主機一旦失守，地端與雲端同時淪陷，卻常被當成一般伺服器管理。"],
      ["TbHourglassLow", "人工盤點跟不上", "帳號、群組、權限關係數以萬計，靠人工逐項檢查只能一年一次，而且難以判斷先修哪裡。"],
    ];
    for (let i = 0; i < 3; i++) {
      const x = 0.6 + i * 4.1;
      L.card(pres, s, x, 1.5, 3.85, 3.95, { name: `ch-${i}` });
      await L.badge(pres, s, x + 0.35, 1.85, 0.9, cards[i][0], HEX.accent2, `ch-${i}`);
      text(s, cards[i][1], { x: x + 0.35, y: 3.0, w: 3.2, h: 0.5, fontSize: 20, bold: true });
      text(s, cards[i][2], { x: x + 0.35, y: 3.6, w: 3.2, h: 1.7, fontSize: 16, color: HEX.muted });
    }
    text(s, "需要的是：能依每個法人現況自動調整、並告訴我們「先修哪一個」的方法", { x: 0.6, y: 5.85, w: 12.1, h: 0.5, fontSize: 18, bold: true, color: HEX.accent1 });
  }

  // ================================================================ 做法
  pres.addSection({ title: "做法" });
  {
    const s = content("做法", "做法：先偵測、後運行");
    const steps = [["TbScan", "自動盤點", "讀取 AD、Entra 與現有工具，產出每個法人的環境指紋"],
      ["TbListDetails", "規則判定", "依環境決定啟用哪些防護，並列出缺口與補強順序"],
      ["TbShieldCheck", "分級運行", "只啟用符合現況的模組，環境改善後自動升級"]];
    for (let i = 0; i < 3; i++) {
      const x = 0.6 + i * 4.1;
      await L.badge(pres, s, x, 1.5, 0.85, steps[i][0], HEX.accent1, `st-${i}`);
      if (i < 2) L.arrow(pres, s, x + 1.0, 1.925, x + 4.0, 1.925, { color: HEX.line, width: 1.5 });
      text(s, steps[i][1], { x, y: 2.55, w: 3.8, h: 0.5, fontSize: 22, bold: true });
      text(s, steps[i][2], { x, y: 3.1, w: 3.6, h: 0.9, fontSize: 15, color: HEX.muted });
    }
    const prof = [
      ["A 完整型", "已有 MDI、SIEM 與完整日誌", "預防評估 + 攻擊路徑 + 威脅偵測", HEX.accent1, HEX.tealTint],
      ["B 部分型", "混合環境，工具或日誌不足", "預防評估 + 攻擊路徑，先補日誌", HEX.accent2, HEX.amberTint],
      ["C 地端型", "只有地端 AD，遙測未知", "預防評估 + 攻擊路徑，先建基礎", HEX.accent3, HEX.redTint],
    ];
    prof.forEach(([t, cond, en, col, tint], i) => {
      const x = 0.6 + i * 4.1;
      L.card(pres, s, x, 4.35, 3.85, 2.35, { fill: tint, name: `pf-${i}` });
      text(s, t, { x: x + 0.3, y: 4.55, w: 3.3, h: 0.5, fontSize: 20, bold: true, color: col });
      text(s, cond, { x: x + 0.3, y: 5.1, w: 3.3, h: 0.45, fontSize: 14, color: HEX.muted });
      text(s, en, { x: x + 0.3, y: 5.6, w: 3.3, h: 0.9, fontSize: 15, bold: true });
    });
    s.addNotes("三種 Profile 由平台自動判定，不需要人工分類。子公司若受法規限制，可改為就地分析、只回傳彙總結果。");
  }
  {
    const s = content("做法", "模擬驗證：路徑普遍存在，但一處修補就能切斷大多數");
    text(s, "100%", { x: 0.6, y: 1.45, w: 4.2, h: 1.1, fontSize: 66, bold: true, color: HEX.accent2 });
    text(s, "三個模擬法人的一般帳號，全都存在通往最高權限的路徑（348 / 348）", { x: 0.6, y: 2.6, w: 4.2, h: 0.9, fontSize: 16 });
    text(s, "96.6%", { x: 0.6, y: 3.65, w: 4.2, h: 1.1, fontSize: 66, bold: true, color: HEX.accent1 });
    text(s, "總公司只要移除一個憑證範本的註冊權，就切斷 234 個帳號中的 226 個", { x: 0.6, y: 4.8, w: 4.2, h: 0.9, fontSize: 16 });
    s.addChart(pres.charts.BAR, [
      { name: "修補前", labels: ["總公司", "子公司 A", "子公司 B"], values: [234, 77, 37] },
      { name: "第一步修補後", labels: ["總公司", "子公司 A", "子公司 B"], values: [8, 33, 0] },
    ], {
      x: 5.3, y: 1.4, w: 7.4, h: 4.6, barDir: "col", barGrouping: "clustered", chartColors: [HEX.accent2, HEX.accent1],
      showTitle: true, title: "可到達最高權限的帳號數", titleFontSize: 14, titleColor: HEX.dk1, titleFontFace: "+mn-lt",
      showValue: true, dataLabelPosition: "outEnd", dataLabelFontSize: 12, dataLabelColor: HEX.dk1, dataLabelFontFace: "+mn-lt",
      catAxisLabelColor: HEX.muted, valAxisLabelColor: HEX.muted, catAxisLabelFontFace: "+mn-lt", valAxisLabelFontFace: "+mn-lt",
      catAxisLabelFontSize: 13, valAxisLabelFontSize: 11, valGridLine: { color: "E3E7EC", size: 0.5 }, catGridLine: { style: "none" },
      showLegend: true, legendPos: "b", legendFontSize: 12, legendFontFace: "+mn-lt", legendColor: HEX.muted, valAxisMaxVal: 250,
    });
    L.card(pres, s, 0.6, 6.0, 12.13, 0.7, { fill: HEX.lt2, name: "note" });
    text(s, "以上為模擬資料（依常見弱點設計的三個虛擬法人），實際數字將於總公司試行後回報", { x: 0.85, y: 6.0, w: 11.6, h: 0.7, fontSize: 14, color: HEX.muted, valign: "middle" });
    s.addNotes("模擬資料刻意埋入常見弱點：憑證範本設定不當、管理員在一般主機登入、群組權限過大。真實環境的數字可能更好也可能更差，重點是平台能找出「先修哪一個」。");
  }

  // ================================================================ 效益
  pres.addSection({ title: "效益" });
  {
    const s = content("效益", "AI 帶來的改變：把專家判斷變成可重複的流程");
    const hdr = (t) => ({ text: t, options: { bold: true, color: "FFFFFF", fill: { color: HEX.dk2 } } });
    const rows = [
      [hdr("工作"), hdr("過去"), hdr("導入後")],
      [{ text: "環境盤點", options: { bold: true } }, "人工逐台查詢，約一年一次", { text: "自動產出環境指紋，每季重跑並比對差異", options: { color: HEX.accent1, bold: true } }],
      [{ text: "風險排序", options: { bold: true } }, "依通用嚴重度，難判斷先修哪個", { text: "依實際攻擊路徑排序，算出每步修補效果", options: { color: HEX.accent1, bold: true } }],
      [{ text: "子公司比較", options: { bold: true } }, "各自為政，報告格式不一", { text: "同一套規則與指標，可直接比較", options: { color: HEX.accent1, bold: true } }],
      [{ text: "專家問答", options: { bold: true } }, "排隊等資安專家查證", { text: "自然語言即問即答，答案引用工具數據", options: { color: HEX.accent1, bold: true } }],
      [{ text: "稽核佐證", options: { bold: true } }, "事後補資料", { text: "每次分析自動留下防竄改紀錄", options: { color: HEX.accent1, bold: true } }],
    ];
    s.addTable(rows, { x: 0.6, y: 1.45, w: 12.13, colW: [2.2, 4.4, 5.53], fontSize: 16, color: HEX.dk1, rowH: 0.72,
      border: { type: "solid", pt: 0.75, color: HEX.line }, valign: "middle", margin: [0.06, 0.15, 0.06, 0.15] });
    await L.badge(pres, s, 0.6, 6.05, 0.55, "TbChartLine", HEX.dk2, "kpi-note");
    text(s, "工時與成本效益將於 Phase 0 量測現況基準後，以實測數據回報，不預先假設", { x: 1.35, y: 6.05, w: 11.3, h: 0.55, fontSize: 15, color: HEX.muted, valign: "middle" });
    s.addNotes("AI 在這裡的角色是放大資安團隊：把需要專家經驗的盤點、排序、解讀變成每季可重跑的流程。我們刻意不在現在給出工時節省百分比，會在試行時量測。");
  }
  {
    const s = content("效益", "對公司 AD 安全的具體收穫");
    const items = [
      ["TbCrown", "守住最高權限", "通往 Domain Admins 與雲端全域管理員的路徑，從看不見變成可計數、可追蹤"],
      ["TbPlugConnected", "補上混合交界面", "Entra Connect、AD FS、憑證服務自動列入最高等級保護"],
      ["TbBuildingCommunity", "子公司一致基準", "每個法人都有同一套 Profile、缺口清單與修補順序"],
      ["TbFileCertificate", "稽核與客戶要求", "防竄改紀錄與每季報告，可作為 ISO 27001、SEMI E187 與客戶稽核佐證"],
    ];
    for (let i = 0; i < 4; i++) {
      const x = 0.6 + (i % 2) * 6.15, y = 1.6 + Math.floor(i / 2) * 2.55;
      L.card(pres, s, x, y, 5.95, 2.25, { name: `gain-${i}` });
      await L.badge(pres, s, x + 0.35, y + 0.4, 0.95, items[i][0], HEX.accent1, `gain-${i}`);
      text(s, items[i][1], { x: x + 1.6, y: y + 0.4, w: 4.1, h: 0.5, fontSize: 21, bold: true });
      text(s, items[i][2], { x: x + 1.6, y: y + 1.0, w: 4.1, h: 1.1, fontSize: 16, color: HEX.muted });
    }
  }

  // ================================================================ 治理
  pres.addSection({ title: "治理" });
  {
    const s = content("治理", "AI 不碰權限：四項保證");
    const g = [
      ["TbEyeCheck", "只讀不寫", "AI 只能查詢，沒有任何修改帳號或設定的能力；技術上設有四道獨立防線"],
      ["TbServerBolt", "資料不出公司", "使用公司地端 GPU 上的模型，權限資料與分析結果都留在內部"],
      ["TbUsersGroup", "變更須人工核准", "一般變更單人核准，最高權限相關變更須兩人核准才可執行"],
      ["TbHistory", "全程可稽核", "每次查詢、分析與被拒絕的操作都留下防竄改紀錄"],
    ];
    for (let i = 0; i < 4; i++) {
      const x = 0.6 + i * 3.08;
      L.card(pres, s, x, 1.5, 2.85, 4.2, { name: `g-${i}` });
      await L.badge(pres, s, x + 0.3, 1.85, 1.0, g[i][0], HEX.accent1, `g-${i}`);
      text(s, g[i][1], { x: x + 0.3, y: 3.1, w: 2.35, h: 0.5, fontSize: 21, bold: true });
      text(s, g[i][2], { x: x + 0.3, y: 3.7, w: 2.3, h: 1.8, fontSize: 15, color: HEX.muted });
    }
    L.card(pres, s, 0.6, 5.95, 12.13, 0.75, { fill: HEX.dk2, name: "tier0-band" });
    text(s, "AI 平台本身握有完整權限關係圖，因此以最高等級（Tier 0）隔離與管理", { x: 0.9, y: 5.95, w: 11.6, h: 0.75, fontSize: 16, color: "FFFFFF", valign: "middle" });
    s.addNotes("AI 平台本身握有完整權限關係圖，等同攻擊者的藍圖，因此平台以最高等級（Tier 0）隔離與管理。");
  }
  {
    const s = content("治理", "路線圖：四階段逐步放寬，過閘門才推進");
    const ph = [
      ["Phase 0", "基礎與盤點", "資料分級、AI 平台、自動盤點", true],
      ["Phase 1", "看見風險", "預防評估、攻擊路徑、日誌補強", false],
      ["Phase 2", "偵測與分流", "AI 告警分流、偵測規則自動化", false],
      ["Phase 3", "硬化與擴展", "人工核准變更、擴展至子公司", false],
    ];
    ph.forEach(([p, t, d, now], i) => {
      const x = 0.6 + i * 3.08;
      L.card(pres, s, x, 2.05, 2.85, 2.55, { fill: now ? HEX.tealTint : HEX.lt2, line: now ? HEX.accent1 : null, name: `ph-${i}` });
      text(s, p, { x: x + 0.25, y: 2.25, w: 2.4, h: 0.4, fontSize: 14, bold: true, color: now ? HEX.accent1 : HEX.muted });
      text(s, t, { x: x + 0.25, y: 2.7, w: 2.4, h: 0.5, fontSize: 21, bold: true });
      text(s, d, { x: x + 0.25, y: 3.3, w: 2.4, h: 1.1, fontSize: 14, color: HEX.muted });
    });
    L.chip(pres, s, 0.6, 1.45, 2.85, "目前：MVP 已完成，待 LAB 驗證", { fill: HEX.accent1, color: "FFFFFF", fontSize: 12, h: 0.38, name: "now" });
    L.arrow(pres, s, 0.6, 5.1, 12.73, 5.1, { color: HEX.accent5, width: 1.5 });
    const gates = [["G0", "資料分級核定\n模型評測達標"], ["G1", "最高權限路徑基準建立\n日誌覆蓋達標"], ["G2", "偵測驗證通過\nAI 分流準確率達標"]];
    gates.forEach(([g, c], i) => {
      const x = 0.6 + (i + 1) * 3.08 - 0.115;
      s.addShape(pres.shapes.DIAMOND, { x: x - 0.2, y: 4.9, w: 0.4, h: 0.4, fill: { color: HEX.dk2 }, line: { color: HEX.dk2 }, objectName: `gate-${g}` });
      text(s, g, { x: x - 0.8, y: 5.4, w: 1.6, h: 0.4, fontSize: 15, bold: true, align: "center" });
      text(s, c, { x: x - 1.4, y: 5.8, w: 2.8, h: 0.8, fontSize: 13, color: HEX.muted, align: "center" });
    });
    s.addNotes("每個閘門未達標就不進下一階段，AI 的權限也隨階段逐步放寬：Phase 0–1 只讀，Phase 2 可開工單，Phase 3 才在人工核准後執行變更。各階段工期待預算與人力核定後排定。");
  }
  {
    const s = content("治理", "成效如何衡量：每季回報五項指標");
    const k = [
      ["通往最高權限的路徑數", "↓", "每月重算，追蹤下降趨勢", HEX.accent2],
      ["高風險發現平均修補天數", "↓", "評估報告前後比對", HEX.accent2],
      ["日誌覆蓋率", "↑", "稽核原則與日誌送達比例", HEX.accent1],
      ["攻擊手法偵測覆蓋率", "↑", "經演練驗證會觸發的手法數（Phase 2 起）", HEX.accent1],
      ["已導入法人數", "↑", "完成盤點並啟用防護的法人", HEX.accent1],
    ];
    k.forEach(([t, dir, d, col], i) => {
      const y = 1.45 + i * 0.98;
      L.card(pres, s, 0.6, y, 12.13, 0.85, { name: `k-${i}` });
      text(s, dir, { x: 0.85, y, w: 0.6, h: 0.85, fontSize: 30, bold: true, color: col, valign: "middle" });
      text(s, t, { x: 1.6, y, w: 5.2, h: 0.85, fontSize: 19, bold: true, valign: "middle" });
      text(s, d, { x: 6.9, y, w: 5.6, h: 0.85, fontSize: 15, color: HEX.muted, valign: "middle" });
    });
    text(s, "基準值於 Phase 0 盤點後量測，目標值依基準訂定", { x: 0.6, y: 6.45, w: 8, h: 0.35, fontSize: 13, color: HEX.muted });
  }
  {
    const s = content("治理", "主要風險與對策");
    const hdr = (t) => ({ text: t, options: { bold: true, color: "FFFFFF", fill: { color: HEX.dk2 } } });
    const r = [
      [hdr("風險"), hdr("影響"), hdr("對策")],
      ["AI 平台本身成為攻擊目標", "權限藍圖外洩", "以最高等級隔離、專用管理工作站、存取全程稽核"],
      ["硬化動作影響產線或研發", "停工", "先開稽核模式觀察、分批導入、備妥回滾計畫"],
      ["子公司配合度不一", "範圍縮減", "管理層授權、分級導入、可選就地分析"],
      ["地端模型品質不穩", "分析錯誤", "上線前評測門檻；報告數字不經 AI 改寫"],
    ];
    s.addTable(r, { x: 0.6, y: 1.45, w: 12.13, colW: [3.8, 2.2, 6.13], fontSize: 16, color: HEX.dk1, rowH: 0.85,
      border: { type: "solid", pt: 0.75, color: HEX.line }, valign: "middle", margin: [0.06, 0.15, 0.06, 0.15] });
    await L.badge(pres, s, 0.6, 6.0, 0.55, "TbInfoCircle", HEX.dk2, "risk-note");
    text(s, "完整風險清單與對策見專案計畫書", { x: 1.35, y: 6.0, w: 10, h: 0.55, fontSize: 15, color: HEX.muted, valign: "middle" });
  }

  // ================================================================ 決策
  pres.addSection({ title: "決策" });
  {
    const s = content("決策", "需要您支持的三件事");
    const asks = [
      ["核定 AD 資料分級", "權限關係圖與弱點報告列為極機密，作為平台存取與分發的依據（Phase 0 閘門條件）"],
      ["授權子公司導入", "由管理層發起，並確認各子公司資料可否回傳總公司或改為就地分析"],
      ["以總公司為第一個試行點", "AD 與 IAM 團隊配合 LAB 驗證與修補排程，試行結果作為子公司導入範本"],
    ];
    asks.forEach(([t, d], i) => {
      const y = 1.5 + i * 1.45;
      L.numBadge(pres, s, 0.6, y + 0.1, 0.8, i + 1, HEX.accent1);
      text(s, t, { x: 1.7, y: y + 0.05, w: 6.4, h: 0.5, fontSize: 22, bold: true });
      text(s, d, { x: 1.7, y: y + 0.6, w: 6.4, h: 0.75, fontSize: 15, color: HEX.muted });
    });
    L.card(pres, s, 8.6, 1.5, 4.13, 4.25, { fill: HEX.lt2, name: "next30" });
    text(s, "核准後 30 天", { x: 8.9, y: 1.75, w: 3.6, h: 0.45, fontSize: 19, bold: true });
    text(s, [
      { text: "LAB 完成部署與實機驗證", options: { bullet: true, breakLine: true } },
      { text: "總公司首次盤點與缺口報告", options: { bullet: true, breakLine: true } },
      { text: "地端模型評測與分工定案", options: { bullet: true, breakLine: true } },
      { text: "第一份最高權限路徑報告", options: { bullet: true } },
    ], { x: 8.9, y: 2.35, w: 3.6, h: 3.2, fontSize: 15, paraSpaceAfter: 12 });
    text(s, "預算、人力與起始日期為待核定事項", { x: 0.6, y: 6.1, w: 7.5, h: 0.45, fontSize: 14, color: HEX.muted });
    s.addNotes("三項請求都不需要新增採購：模型與 GPU 為既有資源，平台為內部自建。需要的是資料分級的決策與跨單位配合。");
  }
  {
    const s = pres.addSlide({ masterName: "TITLE_DARK", sectionTitle: "決策" });
    s.addText("謝謝", { placeholder: "title" });
    s.addText("技術細節請參閱〈hybrid-idsec 技術架構〉簡報與專案計畫書", { placeholder: "body" });
  }

  await L.finish(pres, OUT);
  console.log("written", OUT);
})().catch((e) => { console.error(e); process.exit(1); });
