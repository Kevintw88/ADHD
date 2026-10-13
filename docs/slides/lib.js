// 兩份簡報共用：主題、版面（layouts）、圖示與繪圖小工具。
// 色彩語意：teal = 控制／唯讀／核准；amber = 風險／攻擊路徑；deep navy = 封面與章節。
const path = require("path");
const fs = require("fs");
const JSZip = require(require.resolve("jszip", { paths: [require.resolve("pptxgenjs")] }));
const React = require("react");
const ReactDOMServer = require("react-dom/server");
const sharp = require("sharp");
const TB = require("react-icons/tb");

const SKILL = "/root/.claude/skills/synced/f39238c2-0efc-481f-9c19-13b9be26b428_8da3ef66-b8da-492e-9bb0-638a0401f1aa/pptx";
const { applyTheme } = require(path.join(SKILL, "scripts/apply_theme.js"));

const THEME = {
  name: "Identity Guard",
  headFontFace: "Calibri",
  bodyFontFace: "Calibri",
  eaFontFace: "Microsoft JhengHei", // 中文字型（寫進主題的 <a:ea>）
  colors: {
    dk1: "1B2430", lt1: "FFFFFF", dk2: "0F2A3A", lt2: "EEF2F5",
    accent1: "0E8F7E", // teal：控制、唯讀、核准
    accent2: "D9922E", // amber：風險、攻擊路徑
    accent3: "C2410C", // 嚴重
    accent4: "3B6EA8", // AI 層資訊色
    accent5: "6B7A8F", // 中性
    accent6: "9FD8CF", // 淺 teal（深底上的強調字）
    hlink: "0E8F7E", folHlink: "6B7A8F",
  },
};
const HEX = { ...THEME.colors, muted: "5B6472", line: "B8C1CC", tealTint: "E3F3F0", amberTint: "FBF0DF", redTint: "FBE7DE", blueTint: "E6EEF7" };

const W = 13.333, H = 7.5;

function setup(pres, deckLabel) {
  pres.layout = "LAYOUT_WIDE";
  pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
  pres.author = "TsungYing Pai";
  pres.company = "Realtek Security";
  const C = pres.SchemeColor;

  const motif = []; // 封面右上角的「攻擊路徑」節點圖樣
  const nodes = [[10.2, 1.0], [11.3, 0.6], [12.2, 1.3], [11.0, 1.7], [12.4, 2.4], [10.4, 2.3]];
  const links = [[0, 1], [1, 2], [0, 3], [3, 2], [2, 4], [3, 5]];
  for (const [a, b] of links) {
    const [x1, y1] = nodes[a], [x2, y2] = nodes[b];
    motif.push({ line: { x: Math.min(x1, x2), y: Math.min(y1, y2), w: Math.abs(x2 - x1) || 0.001, h: Math.abs(y2 - y1) || 0.001,
      flipH: (x2 < x1) !== (y2 < y1), line: { color: HEX.accent1, width: 1.25, transparency: 40 } } });
  }
  nodes.forEach(([x, y], i) => motif.push({ rect: { x: x - 0.09, y: y - 0.09, w: 0.18, h: 0.18, rectRadius: 0.09,
    fill: { color: i === 4 ? HEX.accent2 : HEX.accent1 }, line: { color: i === 4 ? HEX.accent2 : HEX.accent1 } } }));

  pres.defineSlideMaster({
    title: "TITLE_DARK",
    background: { color: HEX.dk2 },
    objects: [
      ...motif.map((m) => (m.line ? { line: { ...m.line } } : { rect: { ...m.rect } })),
      { placeholder: { options: { name: "title", type: "title", x: 0.8, y: 2.35, w: 11.2, h: 1.5, fontSize: 40, bold: true,
        color: C.background1, valign: "bottom", align: "left", margin: 0 }, text: "" } },
      { placeholder: { options: { name: "body", type: "body", x: 0.8, y: 4.05, w: 11.2, h: 1.2, fontSize: 18,
        color: C.accent6, valign: "top", margin: 0 }, text: "" } },
      { text: { text: deckLabel, options: { x: 0.8, y: 6.6, w: 8, h: 0.4, fontSize: 12, color: "AFC3D0", margin: 0 } } },
    ],
  });
  pres.defineSlideMaster({
    title: "SECTION_DARK",
    background: { color: HEX.dk2 },
    objects: [
      { placeholder: { options: { name: "num", type: "body", x: 0.8, y: 2.2, w: 3, h: 1.0, fontSize: 54, bold: true,
        color: C.accent6, margin: 0, valign: "bottom" }, text: "" } },
      { placeholder: { options: { name: "title", type: "title", x: 0.8, y: 3.3, w: 11.5, h: 1.0, fontSize: 36, bold: true,
        color: C.background1, margin: 0, valign: "top", align: "left" }, text: "" } },
      { placeholder: { options: { name: "body", type: "body", x: 0.8, y: 4.4, w: 11.5, h: 0.9, fontSize: 16,
        color: "AFC3D0", margin: 0, valign: "top" }, text: "" } },
    ],
  });
  pres.defineSlideMaster({
    title: "CONTENT",
    background: { color: HEX.lt1 },
    margin: [0.5, 0.6, 0.6, 0.6],
    objects: [
      { placeholder: { options: { name: "title", type: "title", x: 0.6, y: 0.35, w: 12.1, h: 0.85, fontSize: 30, bold: true,
        color: C.text1, valign: "middle", align: "left", margin: 0 }, text: "" } },
      { text: { text: deckLabel, options: { x: 0.6, y: 7.05, w: 9, h: 0.3, fontSize: 10, color: HEX.muted, margin: 0 } } },
    ],
    slideNumber: { x: 12.23, y: 7.05, w: 0.5, h: 0.3, fontSize: 10, color: HEX.muted, align: "right" },
  });
  return C;
}

// ---------------------------------------------------------------- 圖示
const iconCache = {};
async function icon(name, color = "FFFFFF", size = 256) {
  const key = `${name}-${color}`;
  if (iconCache[key]) return iconCache[key];
  const Comp = TB[name];
  if (!Comp) throw new Error(`找不到圖示 ${name}`);
  const svg = ReactDOMServer.renderToStaticMarkup(React.createElement(Comp, { color: `#${color}`, size: String(size) }));
  const buf = await sharp(Buffer.from(svg)).resize(size, size).png().toBuffer();
  iconCache[key] = "image/png;base64," + buf.toString("base64");
  return iconCache[key];
}

// 圓形圖示徽章（全簡報的視覺母題）
async function badge(pres, slide, x, y, d, iconName, fill = HEX.accent1, name = "badge") {
  slide.addShape(pres.shapes.OVAL, { x, y, w: d, h: d, fill: { color: fill }, line: { color: fill }, objectName: `${name}-circle` });
  const pad = d * 0.22;
  slide.addImage({ data: await icon(iconName), x: x + pad, y: y + pad, w: d - 2 * pad, h: d - 2 * pad, objectName: `${name}-icon` });
}

// 數字徽章
function numBadge(pres, slide, x, y, d, n, fill = HEX.accent1, color = "FFFFFF") {
  slide.addShape(pres.shapes.OVAL, { x, y, w: d, h: d, fill: { color: fill }, line: { color: fill }, objectName: `num-${n}` });
  slide.addText(String(n), { x, y, w: d, h: d, align: "center", valign: "middle", fontSize: Math.round(d * 30), bold: true,
    color, margin: 0, isTextBox: true, objectName: `num-${n}-text` });
}

// 圓角卡片
function card(pres, slide, x, y, w, h, { fill = HEX.lt2, line = null, dash = null, name = "card" } = {}) {
  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: 0.08, fill: { color: fill },
    line: line ? { color: line, width: 1.25, dashType: dash || "solid" } : { color: fill, width: 0 }, objectName: name });
}

// 方框（名稱 + 說明），用於架構圖
function box(pres, slide, x, y, w, h, title, sub, { style = "box", titleSize = 13, subSize = 11, name } = {}) {
  const styles = {
    box: { fill: "FFFFFF", line: HEX.line, dash: "solid" },
    accent: { fill: HEX.tealTint, line: HEX.accent1, dash: "solid" },
    amber: { fill: HEX.amberTint, line: HEX.accent2, dash: "solid" },
    dashed: { fill: "FFFFFF", line: HEX.line, dash: "dash" },
    blue: { fill: HEX.blueTint, line: HEX.accent4, dash: "solid" },
  }[style];
  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: 0.06, fill: { color: styles.fill },
    line: { color: styles.line, width: style === "accent" ? 2 : 1, dashType: styles.dash }, objectName: name || `box-${title}` });
  const runs = [{ text: title, options: { bold: true, fontSize: titleSize, color: HEX.dk1, breakLine: !!sub } }];
  if (sub) runs.push({ text: sub, options: { fontSize: subSize, color: HEX.muted } });
  slide.addText(runs, { x, y, w, h, align: "center", valign: "middle", margin: 0.04, isTextBox: true, paraSpaceAfter: 2,
    objectName: `${name || "box-" + title}-text` });
}

// 直線箭頭（水平或垂直）
function arrow(pres, slide, x1, y1, x2, y2, { color = HEX.accent5, dash = "solid", head = true, width = 1.25 } = {}) {
  const opts = { x: Math.min(x1, x2), y: Math.min(y1, y2), w: Math.max(Math.abs(x2 - x1), 0.0001), h: Math.max(Math.abs(y2 - y1), 0.0001),
    line: { color, width, dashType: dash, endArrowType: head ? "triangle" : undefined } };
  if (x2 < x1) opts.flipH = true;
  if (y2 < y1) opts.flipV = true;
  slide.addShape(pres.shapes.LINE, opts);
}
// 折線箭頭：points = [[x,y], ...]，最後一段帶箭頭
function elbow(pres, slide, points, opts = {}) {
  for (let i = 0; i < points.length - 1; i++) {
    const [x1, y1] = points[i], [x2, y2] = points[i + 1];
    arrow(pres, slide, x1, y1, x2, y2, { ...opts, head: i === points.length - 2 });
  }
}

// 程式碼區塊
function code(pres, slide, x, y, w, h, text, { fontSize = 12, name = "code" } = {}) {
  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: 0.06, fill: { color: "16232E" }, line: { color: "16232E" }, objectName: name });
  slide.addText(text, { x: x + 0.15, y: y + 0.1, w: w - 0.3, h: h - 0.2, fontFace: "Consolas", fontSize, color: "D6E2EA",
    valign: "top", margin: 0, isTextBox: true, objectName: `${name}-text` });
}

// 狀態標籤
function chip(pres, slide, x, y, w, text, { fill = HEX.tealTint, color = HEX.accent1, h = 0.32, fontSize = 11, name } = {}) {
  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: h / 2, fill: { color: fill }, line: { color: fill }, objectName: name || `chip-${text}` });
  slide.addText(text, { x, y, w, h, align: "center", valign: "middle", fontSize, bold: true, color, margin: 0, isTextBox: true,
    objectName: `${name || "chip-" + text}-text` });
}

// 寫檔 → 主題色 → 主題中文字型
async function finish(pres, file) {
  await pres.writeFile({ fileName: file });
  await applyTheme(file, THEME);
  const zip = await JSZip.loadAsync(fs.readFileSync(file));
  for (const name of Object.keys(zip.files).filter((n) => /^ppt\/theme\/theme\d+\.xml$/.test(n))) {
    let xml = await zip.file(name).async("string");
    xml = xml.replace(/<a:ea typeface="[^"]*"\s*\/>/g, `<a:ea typeface="${THEME.eaFontFace}"/>`);
    zip.file(name, xml);
  }
  fs.writeFileSync(file, await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" }));
}

module.exports = { THEME, HEX, W, H, setup, icon, badge, numBadge, card, box, arrow, elbow, code, chip, finish };
