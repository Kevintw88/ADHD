"""Offline HTML dashboard (report.html): one self-contained file, no network, no external assets.

The analysis document (the same content as findings.json, with long affected lists capped) is embedded
as JSON and rendered by inline vanilla JS; every label is inserted with textContent.  Opens from disk in
any browser on the air-gapped analysis host.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

HTML_AFFECTED_LIMIT = 500


def _payload(doc: dict[str, Any]) -> str:
    d = copy.deepcopy(doc)
    for f in d.get("findings", []):
        if len(f.get("affected") or []) > HTML_AFFECTED_LIMIT:
            f["affectedTruncated"] = len(f["affected"]) - HTML_AFFECTED_LIMIT
            f["affected"] = f["affected"][:HTML_AFFECTED_LIMIT]
    text = json.dumps(d, ensure_ascii=False, default=str)
    # keep the JSON inert inside <script type="application/json">
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026") \
               .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def write_html(doc: dict[str, Any], path: Path) -> None:
    title = f"ADHD 評估 — {doc.get('scope', {}).get('adDomain') or doc.get('scope', {}).get('entraTenantId') or ''}"
    html = (_TEMPLATE.replace("__TITLE__", _esc(title))
            .replace("__DATA__", _payload(doc)))
    path.write_text(html, encoding="utf-8")


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


_TEMPLATE = r"""<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<title>__TITLE__</title>
<style>
:root {
  color-scheme: light;
  --page: #f9f9f7; --surface: #fcfcfb; --surface-2: #f3f2ee;
  --ink: #0b0b0b; --ink-2: #52514e; --muted: #77756f;
  --grid: #e1e0d9; --axis: #c3c2b7; --ring: rgba(11,11,11,0.10);
  --accent: #2a78d6; --accent-track: #cde2fb; --accent-ink: #1c5cab;
  --sev-critical: #d03b3b; --sev-high: #ec835a; --sev-medium: #fab219; --sev-low: #898781; --sev-info: #c3c2b7;
  --t0-bg: #fbeaea; --t0-ink: #8f2323;
  --heat-1: #e8f1fd; --heat-2: #cde2fb; --heat-3: #9ec5f4; --heat-4: #6da7ec;
}
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) {
    color-scheme: dark;
    --page: #0d0d0d; --surface: #1a1a19; --surface-2: #232321;
    --ink: #f0efec; --ink-2: #c3c2b7; --muted: #9a988f;
    --grid: #2c2c2a; --axis: #383835; --ring: rgba(255,255,255,0.10);
    --accent: #3987e5; --accent-track: #1d3554; --accent-ink: #86b6ef;
    --t0-bg: #3a1f1f; --t0-ink: #f2b8b8;
    --heat-1: #172739; --heat-2: #1c3a5e; --heat-3: #22508a; --heat-4: #2d6bb8;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --page: #0d0d0d; --surface: #1a1a19; --surface-2: #232321;
  --ink: #f0efec; --ink-2: #c3c2b7; --muted: #9a988f;
  --grid: #2c2c2a; --axis: #383835; --ring: rgba(255,255,255,0.10);
  --accent: #3987e5; --accent-track: #1d3554; --accent-ink: #86b6ef;
  --t0-bg: #3a1f1f; --t0-ink: #f2b8b8;
  --heat-1: #172739; --heat-2: #1c3a5e; --heat-3: #22508a; --heat-4: #2d6bb8;
}
* { box-sizing: border-box; }
html, body { margin: 0; background: var(--page); color: var(--ink);
  font: 14px/1.55 system-ui, -apple-system, "Segoe UI", "Noto Sans TC", "Microsoft JhengHei", sans-serif; }
a { color: var(--accent-ink); }
header.top { position: sticky; top: 0; z-index: 5; background: var(--page); border-bottom: 1px solid var(--grid); }
.wrap { max-width: 1240px; margin: 0 auto; padding: 0 20px; }
.top .wrap { display: flex; align-items: center; gap: 16px; min-height: 52px; flex-wrap: wrap; }
.top h1 { font-size: 16px; margin: 0; font-weight: 650; }
.top nav { display: flex; gap: 4px; flex-wrap: wrap; }
.top nav a { padding: 6px 10px; border-radius: 6px; color: var(--ink-2); text-decoration: none; }
.top nav a:hover { background: var(--surface-2); color: var(--ink); }
.spacer { flex: 1; }
button.theme { border: 1px solid var(--grid); background: var(--surface); color: var(--ink-2); border-radius: 6px; padding: 5px 10px; cursor: pointer; font: inherit; }
main { padding: 20px 0 60px; }
section { margin: 0 0 28px; scroll-margin-top: 64px; }
h2 { font-size: 18px; margin: 0 0 4px; font-weight: 650; }
.lead { color: var(--ink-2); margin: 0 0 14px; max-width: 900px; }
.meta { color: var(--ink-2); font-size: 13px; margin: 14px 0 20px; display: flex; flex-wrap: wrap; gap: 4px 18px; }
.meta b { color: var(--ink); font-weight: 600; }
.card { background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; padding: 16px 18px; }
.grid { display: grid; gap: 14px; }
.kpis { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
.tile .label { color: var(--ink-2); font-size: 13px; display: flex; align-items: center; gap: 6px; }
.tile .value { font-size: 30px; font-weight: 650; line-height: 1.2; margin-top: 4px; }
.tile .sub { color: var(--muted); font-size: 12px; }
.dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; flex: none; }
.sev-critical { background: var(--sev-critical); } .sev-high { background: var(--sev-high); }
.sev-medium { background: var(--sev-medium); } .sev-low { background: var(--sev-low); } .sev-info { background: var(--sev-info); }
.sevbadge { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; color: var(--ink-2); white-space: nowrap; }
.sevbadge .glyph { font-size: 10px; color: var(--ink-2); }
.two { grid-template-columns: minmax(0, 1.25fr) minmax(0, 1fr); }
@media (max-width: 900px) { .two { grid-template-columns: minmax(0, 1fr); } }
.meter { margin-top: 10px; }
.meter .track { height: 10px; border-radius: 5px; background: var(--accent-track); overflow: hidden; }
.meter .fill { height: 100%; background: var(--accent); border-radius: 5px 0 0 5px; }
.meter .cap { display: flex; justify-content: space-between; color: var(--ink-2); font-size: 13px; margin-top: 6px; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid var(--grid); vertical-align: top; }
th { font-weight: 600; color: var(--ink-2); font-size: 12px; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.matrix td.num { min-width: 52px; }
.hscroll { overflow-x: auto; }
.matrix a { color: var(--ink); }
.matrix td.cell { text-align: center; font-variant-numeric: tabular-nums; border-radius: 4px; }
.h0 { color: var(--muted); } .h1 { background: var(--heat-1); } .h2 { background: var(--heat-2); } .h3 { background: var(--heat-3); } .h4 { background: var(--heat-4); }
.bars .row { display: grid; grid-template-columns: minmax(0, 1fr) 160px 48px; gap: 10px; align-items: center; padding: 6px 0; border-bottom: 1px solid var(--grid); }
.bars .row:hover { background: var(--surface-2); }
.bars .bar { height: 12px; background: var(--accent); border-radius: 0 4px 4px 0; min-width: 2px; }
.bars .val { text-align: right; font-variant-numeric: tabular-nums; color: var(--ink); }
.step-text { color: var(--ink-2); font-size: 13px; }
.path { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 4px; margin-top: 8px; }
.chip { display: inline-flex; flex-direction: column; border: 1px solid var(--grid); background: var(--surface-2); border-radius: 8px; padding: 4px 9px; max-width: 280px; }
.chip .k { font-size: 11px; color: var(--muted); }
.chip .n { font-weight: 600; overflow-wrap: anywhere; }
.chip.t0 { background: var(--t0-bg); border-color: transparent; }
.chip.t0 .k, .chip.t0 .n { color: var(--t0-ink); }
.arrow { display: inline-flex; flex-direction: column; align-items: center; padding: 0 4px; color: var(--muted); font-size: 12px; max-width: 220px; text-align: center; }
.arrow .a { font-size: 16px; line-height: 1; color: var(--axis); }
.pathcard { padding: 14px 16px; border-bottom: 1px solid var(--grid); }
.pathcard:last-child { border-bottom: 0; }
.pathcard .hd { display: flex; flex-wrap: wrap; gap: 8px 14px; align-items: baseline; }
.pathcard .hd .who { font-weight: 650; }
.tag { display: inline-block; font-size: 11px; padding: 1px 7px; border-radius: 10px; border: 1px solid var(--grid); color: var(--ink-2); }
.tag.broad { border-color: var(--sev-critical); color: var(--ink); }
.filters { display: flex; flex-wrap: wrap; gap: 8px 12px; align-items: center; margin: 0 0 12px; }
.filters label { display: inline-flex; gap: 6px; align-items: center; color: var(--ink-2); font-size: 13px; cursor: pointer; }
.filters input[type=search], .filters select { font: inherit; padding: 6px 9px; border: 1px solid var(--grid); border-radius: 6px; background: var(--surface); color: var(--ink); }
.filters input[type=search] { min-width: 240px; }
.count { color: var(--muted); font-size: 13px; }
details.finding { background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; margin: 0 0 8px; }
details.finding > summary { list-style: none; cursor: pointer; padding: 11px 14px; display: grid; grid-template-columns: 58px 90px 92px minmax(0, 1fr) 56px; gap: 10px; align-items: baseline; }
details.finding > summary::-webkit-details-marker { display: none; }
details.finding > summary:hover { background: var(--surface-2); border-radius: 10px; }
details.finding[open] > summary { border-bottom: 1px solid var(--grid); border-radius: 10px 10px 0 0; }
.fid { font-variant-numeric: tabular-nums; color: var(--muted); }
.rid { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; color: var(--ink-2); }
.ftitle { font-weight: 600; }
.fbody { padding: 12px 16px 16px; }
.fbody p { margin: 0 0 10px; }
.fbody h4 { margin: 14px 0 6px; font-size: 13px; color: var(--ink-2); font-weight: 600; }
.scroll { max-height: 420px; overflow: auto; border: 1px solid var(--grid); border-radius: 8px; }
.scroll table th { position: sticky; top: 0; background: var(--surface); }
.detail { font-size: 12px; color: var(--ink-2); overflow-wrap: anywhere; }
pre.json { font: 12px/1.45 ui-monospace, SFMono-Regular, Consolas, monospace; background: var(--surface-2); padding: 10px; border-radius: 8px; overflow: auto; max-height: 320px; margin: 0; }
.remed { background: var(--surface-2); border-radius: 8px; padding: 10px 12px; }
.status { font-size: 12px; white-space: nowrap; }
.st-skipped { font-weight: 600; }
.note { color: var(--muted); font-size: 12px; margin-top: 8px; }
.empty { color: var(--muted); padding: 14px 0; }
footer { color: var(--muted); font-size: 12px; border-top: 1px solid var(--grid); padding: 16px 0 30px; }
.toggle { font: inherit; font-size: 12px; border: 1px solid var(--grid); background: var(--surface); color: var(--ink-2); border-radius: 6px; padding: 3px 8px; cursor: pointer; }
.cardhd { display: flex; justify-content: space-between; align-items: baseline; gap: 10px; margin-bottom: 8px; }
.cardhd h3 { font-size: 14px; margin: 0; font-weight: 650; }
@media (max-width: 720px) {
  header.top { position: static; }
  details.finding > summary { display: flex; flex-wrap: wrap; gap: 2px 12px; }
  details.finding > summary .fsum { flex-basis: 100%; min-width: 0; }
  details.finding > summary .count { margin-left: auto; }
  .bars .row { grid-template-columns: minmax(0, 1fr) 80px 40px; }
}
@media print {
  header.top, .filters, button { display: none !important; }
  body { background: #fff; }
  .card, details.finding { break-inside: avoid; }
}
</style>
</head>
<body>
<header class="top"><div class="wrap">
  <h1 id="title">ADHD 評估</h1>
  <nav aria-label="區段">
    <a href="#overview">總覽</a><a href="#paths">攻擊路徑</a><a href="#hotspots">重點對象</a>
    <a href="#findings">發現</a><a href="#rules">規則與未評估</a>
  </nav>
  <span class="spacer"></span>
  <button class="theme" id="theme" type="button" aria-label="切換深淺色">主題：自動</button>
</div></header>
<main class="wrap">
  <div class="meta" id="meta"></div>
  <section id="overview" aria-labelledby="h-overview">
    <h2 id="h-overview">總覽</h2>
    <p class="lead">發現來自確定性規則並附證據。帳號名稱為假名（u-xxxxxxxxxxxx），需由資料擁有者以對照表還原。</p>
    <div class="grid kpis" id="kpis"></div>
    <div class="grid two" style="margin-top:14px">
      <div class="card" id="matrix-card"></div>
      <div class="card" id="exposure-card"></div>
    </div>
  </section>
  <section id="paths" aria-labelledby="h-paths">
    <h2 id="h-paths">攻擊路徑</h2>
    <p class="lead">每個起點到 Tier0 的最短一條路徑；起點是實際持有第一個可濫用權限的主體，「影響帳號」是透過群組成員關係共用這條路徑的啟用帳號數。切斷後可能仍有較長的替代路徑，處理後請重新分析。</p>
    <div class="grid two">
      <div class="card" style="padding:0" id="path-list"></div>
      <div class="card" id="choke-card"></div>
    </div>
  </section>
  <section id="hotspots" aria-labelledby="h-hot">
    <h2 id="h-hot">重點對象</h2>
    <p class="lead">同一身分（AD 帳號與其同步的 Entra 帳號合併）出現在多條規則；分數：嚴重 10、高 5、中 2、低 1。</p>
    <div class="card" id="hot-card"></div>
  </section>
  <section id="findings" aria-labelledby="h-find">
    <h2 id="h-find">發現</h2>
    <div class="filters" id="filters" role="search"></div>
    <div id="finding-list"></div>
  </section>
  <section id="rules" aria-labelledby="h-rules">
    <h2 id="h-rules">規則與未評估範圍</h2>
    <p class="lead">「略過」代表需要的資料沒有收到或收集失敗：這些項目<strong>未評估</strong>，不代表沒有問題。</p>
    <div class="card" id="rules-card"></div>
  </section>
  <section id="accepted-sec" aria-labelledby="h-acc" hidden>
    <h2 id="h-acc">已接受的例外</h2>
    <div class="card" id="accepted-card"></div>
  </section>
</main>
<footer><div class="wrap" id="foot"></div></footer>
<script type="application/json" id="adhd-data">__DATA__</script>
<script>
(function () {
  "use strict";
  var D = JSON.parse(document.getElementById("adhd-data").textContent);
  var SEV = ["critical", "high", "medium", "low", "info"];
  var SEV_LABEL = { critical: "嚴重", high: "高", medium: "中", low: "低", info: "資訊" };
  var SEV_GLYPH = { critical: "◆", high: "▲", medium: "●", low: "○", info: "·" };
  var STATUS = { finding: "有發現", pass: "通過", skipped: "略過（未評估）", error: "錯誤", accepted: "已接受例外" };
  var KIND = { user: "使用者", group: "群組", computer: "電腦", gmsa: "gMSA", foreignPrincipal: "外部 / 內建主體",
    localAccount: "本機帳號", entraUser: "Entra 使用者", entraGroup: "Entra 群組", servicePrincipal: "服務主體",
    application: "App 註冊", entraRole: "Entra 角色", domain: "網域", ou: "OU", container: "容器", gpo: "GPO",
    certTemplate: "憑證範本", enterpriseCA: "企業 CA", unknown: "物件" };
  var CATS = ["AD", "ADCS", "Entra", "Hybrid", "Path"];

  function el(tag, props) {
    var e = document.createElement(tag);
    if (props) for (var k in props) {
      var v = props[k];
      if (v == null || v === false) continue;
      if (k === "class") e.className = v;
      else if (k === "text") e.textContent = v;
      else if (k.slice(0, 2) === "on") e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v === true ? "" : v);
    }
    for (var i = 2; i < arguments.length; i++) add(e, arguments[i]);
    return e;
  }
  function add(e) {
    for (var i = 1; i < arguments.length; i++) {
      var c = arguments[i];
      if (c == null || c === false) continue;
      if (Array.isArray(c)) { c.forEach(function (x) { add(e, x); }); continue; }
      e.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
    }
  }
  function fmt(n) { return (n == null ? "—" : Number(n).toLocaleString("zh-Hant")); }
  function sevBadge(s) {
    return el("span", { class: "sevbadge" }, el("span", { class: "dot sev-" + s, "aria-hidden": "true" }),
      el("span", { class: "glyph", "aria-hidden": "true", text: SEV_GLYPH[s] }), SEV_LABEL[s] || s);
  }
  function detailText(d) {
    if (d == null || d === "") return "";
    if (typeof d !== "object") return String(d);
    if (Array.isArray(d)) return d.map(detailText).join(", ");
    return Object.keys(d).filter(function (k) { var v = d[k]; return !(v == null || v === "" || (Array.isArray(v) && !v.length)); })
      .map(function (k) { var v = d[k]; return k + "=" + (typeof v === "object" ? (Array.isArray(v) ? v.join(", ") : JSON.stringify(v)) : v); })
      .join("；");
  }

  // ---- theme -------------------------------------------------------------------------------
  var root = document.documentElement, themeBtn = document.getElementById("theme");
  var modes = ["auto", "light", "dark"], names = { auto: "自動", light: "淺色", dark: "深色" };
  function setTheme(m) {
    if (m === "auto") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", m);
    themeBtn.textContent = "主題：" + names[m];
    try { localStorage.setItem("adhd-theme", m); } catch (e) { /* file:// or private mode */ }
  }
  var saved = "auto";
  try { saved = localStorage.getItem("adhd-theme") || "auto"; } catch (e) { saved = "auto"; }
  setTheme(modes.indexOf(saved) >= 0 ? saved : "auto");
  themeBtn.addEventListener("click", function () {
    var cur = root.getAttribute("data-theme") || "auto";
    setTheme(modes[(modes.indexOf(cur) + 1) % modes.length]);
  });

  // ---- header / meta -----------------------------------------------------------------------
  var scope = D.scope || {}, sum = D.summary || {};
  document.getElementById("title").textContent = "ADHD 評估 — " + (scope.adDomain || scope.entraTenantId || "");
  var meta = document.getElementById("meta");
  [["AD 網域", scope.adDomain ? scope.adDomain + "（" + (scope.adDomainSid || "") + "）" : "—"],
   ["Entra 租用戶", scope.entraTenantId || "—"], ["資料時間", (D.asOfUtc || "") + " UTC"],
   ["分析時間", (D.generatedUtc || "") + " UTC"], ["分析器", (D.analyzer || {}).version]].forEach(function (p) {
    add(meta, el("span", null, p[0] + "：", el("b", { text: p[1] })));
  });
  add(meta, el("span", null, "Bundles：", el("b", { text: (D.bundles || []).map(function (b) {
    return b.bundle + ((b.supersededDatasets || []).length ? "（部分資料集由較新 bundle 取代）" : "");
  }).join("、") })));

  // ---- KPI tiles ---------------------------------------------------------------------------
  var bySev = sum.findingsBySeverity || {};
  var kpis = document.getElementById("kpis");
  ["critical", "high", "medium", "low"].forEach(function (s) {
    add(kpis, el("div", { class: "card tile" }, el("div", { class: "label" }, sevBadge(s), "發現"),
      el("div", { class: "value", text: fmt(bySev[s] || 0) })));
  });
  var rs = sum.rules || {};
  add(kpis, el("div", { class: "card tile" }, el("div", { class: "label", text: "Tier0 主體" }),
    el("div", { class: "value", text: fmt(sum.tier0Principals) }), el("div", { class: "sub", text: "特權群組成員、DC、DCSync 持有者等" })));
  add(kpis, el("div", { class: "card tile" }, el("div", { class: "label", text: "規則" }),
    el("div", { class: "value", text: fmt((rs.finding || 0) + (rs.pass || 0) + (rs.skipped || 0) + (rs.error || 0) + (rs.accepted || 0)) }),
    el("div", { class: "sub", text: "有發現 " + fmt(rs.finding) + "・通過 " + fmt(rs.pass) + "・未評估 " + fmt(rs.skipped) + (rs.error ? "・錯誤 " + rs.error : "") })));

  // ---- category x severity matrix (counts; cell shade = count, one hue) ----------------------
  var counts = {}, maxc = 0;
  (D.findings || []).forEach(function (f) {
    var c = counts[f.category] = counts[f.category] || {};
    c[f.severity] = (c[f.severity] || 0) + 1;
    maxc = Math.max(maxc, c[f.severity]);
  });
  var mc = document.getElementById("matrix-card");
  add(mc, el("div", { class: "cardhd" }, el("h3", { text: "各類別的發現數" }), el("span", { class: "count", text: "點數字可篩選下方清單" })));
  var mt = el("table", { class: "matrix" });
  add(mt, el("thead", null, el("tr", null, el("th", { text: "類別" }), SEV.map(function (s) { return el("th", { class: "num" }, sevBadge(s)); }),
    el("th", { class: "num", text: "合計" }))));
  var tb = el("tbody");
  CATS.concat(Object.keys(counts).filter(function (c) { return CATS.indexOf(c) < 0; })).forEach(function (cat) {
    var c = counts[cat] || {}, total = 0;
    add(tb, el("tr", null, el("td", { text: cat }), SEV.map(function (s) {
      var n = c[s] || 0; total += n;
      var lvl = n === 0 ? 0 : Math.min(4, Math.ceil(4 * n / Math.max(1, maxc)));
      var cell = el("td", { class: "cell h" + lvl, title: cat + "・" + SEV_LABEL[s] + "：" + n });
      if (n) add(cell, el("a", { href: "#findings", text: String(n), onclick: function () { applyFilter({ cat: cat, sev: s }); } }));
      else cell.textContent = "0";
      return cell;
    }), el("td", { class: "num", text: String(total) })));
  });
  add(mt, tb);
  add(mc, el("div", { class: "hscroll" }, mt));

  // ---- exposure ---------------------------------------------------------------------------
  var AP = D.attackPaths || null, NODES = (AP && AP.nodes) || {};
  var ec = document.getElementById("exposure-card");
  add(ec, el("div", { class: "cardhd" }, el("h3", { text: "通往 Tier0 的暴露" })));
  if (!AP) {
    add(ec, el("p", { class: "empty", text: "這次分析沒有攻擊路徑資料（PATH 規則未執行或資料不足）。" }));
  } else {
    var withPath = AP.accountsWithPath || 0, total = AP.accountsTotal || 0, pct = total ? Math.round(100 * withPath / total) : 0;
    add(ec, el("div", { class: "tile" }, el("div", { class: "value", text: withPath + " / " + total }),
      el("div", { class: "sub", text: "啟用中的帳號有通往 Tier0 的路徑" })));
    add(ec, el("div", { class: "meter", role: "img", "aria-label": pct + "% 的啟用帳號有路徑" },
      el("div", { class: "track" }, el("div", { class: "fill", style: "width:" + pct + "%" })),
      el("div", { class: "cap" }, el("span", { text: pct + "%" }), el("span", { text: "起點 " + fmt(AP.entriesTotal) + " 個・攻擊步驟 " + fmt(AP.attackSteps) + " 條" }))));
    var broad = (AP.entries || []).filter(function (e) { return e.broad; });
    add(ec, el("p", { class: "note", text: broad.length
      ? "有 " + broad.length + " 個廣泛群組（例如 Domain Users、Authenticated Users）有路徑：任何一個帳號被入侵即可到達 Tier0。"
      : "沒有廣泛群組（Domain Users、Authenticated Users 等）通往 Tier0 的路徑。" }));
  }

  // ---- attack paths -----------------------------------------------------------------------
  function chip(id, fallbackLabel) {
    var n = NODES[id] || {};
    var label = n.label || fallbackLabel || id;
    return el("span", { class: "chip" + (n.tier0 ? " t0" : ""), title: id + (n.tier0Reason ? "\n" + n.tier0Reason : "") },
      el("span", { class: "k", text: (KIND[n.kind] || n.kind || "物件") + (n.tier0 ? "・Tier0" : "") }), el("span", { class: "n", text: label }));
  }
  function pathView(steps) {
    var box = el("div", { class: "path" });
    if (!steps || !steps.length) return box;
    add(box, chip(steps[0].from, steps[0].fromLabel));
    steps.forEach(function (s) {
      add(box, el("span", { class: "arrow" }, el("span", { class: "t", text: s.action + (s.note ? "（" + s.note + "）" : "") }), el("span", { class: "a", "aria-hidden": "true", text: "→" })));
      add(box, chip(s.to, s.toLabel));
    });
    return box;
  }
  var pl = document.getElementById("path-list");
  if (!AP || !(AP.entries || []).length) {
    add(pl, el("p", { class: "empty", style: "padding:14px 16px", text: "沒有找到通往 Tier0 的路徑（以收集到的資料）。" }));
  } else {
    var SHOW = 12, shown = 0;
    var listBox = el("div");
    function renderPaths(n) {
      listBox.textContent = "";
      AP.entries.slice(0, n).forEach(function (e) {
        add(listBox, el("div", { class: "pathcard" },
          el("div", { class: "hd" }, el("span", { class: "who", text: e.label }),
            el("span", { class: "step-text", text: KIND[e.kind] || e.kind }),
            e.broad ? el("span", { class: "tag broad", text: "廣泛群組" }) : null,
            el("span", { class: "tag", text: e.hops + " 步" }),
            el("span", { class: "tag", text: "影響 " + fmt(e.exposedAccounts) + " 個帳號" }),
            e.crossesAdEntra ? el("span", { class: "tag", text: "跨 AD ↔ Entra" }) : null),
          pathView(e.steps),
          e.targetReason ? el("div", { class: "note", text: "終點：" + e.targetLabel + "（" + e.targetReason + "）" }) : null));
      });
      shown = n;
    }
    renderPaths(Math.min(SHOW, AP.entries.length));
    add(pl, listBox);
    if (AP.entries.length > SHOW) {
      var more = el("div", { style: "padding:10px 16px" });
      var btn = el("button", { class: "toggle", type: "button", text: "顯示全部 " + AP.entries.length + " 個起點" + (AP.entriesTotal > AP.entries.length ? "（共 " + AP.entriesTotal + "，其餘見 findings.json）" : ""),
        onclick: function () { if (shown < AP.entries.length) { renderPaths(AP.entries.length); btn.textContent = "只顯示前 " + SHOW + " 個"; } else { renderPaths(SHOW); btn.textContent = "顯示全部 " + AP.entries.length + " 個起點"; } } });
      add(more, btn); add(pl, more);
    }
  }
  var cc = document.getElementById("choke-card");
  add(cc, el("div", { class: "cardhd" }, el("h3", { text: "優先切斷" }), el("span", { class: "count", text: "經過此步驟的帳號數" })));
  var cps = (AP && AP.chokepoints) || [];
  if (!cps.length) add(cc, el("p", { class: "empty", text: "沒有關鍵步驟。" }));
  else {
    var maxa = Math.max.apply(null, cps.map(function (c) { return c.accounts; }));
    var bars = el("div", { class: "bars", role: "table", "aria-label": "優先切斷的步驟" });
    cps.forEach(function (c) {
      var w = maxa ? Math.max(2, Math.round(100 * c.accounts / maxa)) : 0;
      add(bars, el("div", { class: "row", role: "row", title: c.fromLabel + " →[" + c.action + "]→ " + c.toLabel + "：" + c.accounts + " 個帳號" },
        el("div", { role: "cell" }, el("div", { text: c.fromLabel }), el("div", { class: "step-text", text: "→ " + c.action + " → " + c.toLabel })),
        el("div", { role: "cell" }, el("div", { class: "bar", style: "width:" + w + "%" })),
        el("div", { class: "val", role: "cell", text: fmt(c.accounts) })));
    });
    add(cc, bars);
    add(cc, el("p", { class: "note", text: "依序移除這些權限 / 成員關係 / 主機上的憑證，每切斷一條就重新分析確認。" }));
  }

  // ---- hotspots ---------------------------------------------------------------------------
  var hc = document.getElementById("hot-card"), hs = D.hotspots || [];
  if (!hs.length) add(hc, el("p", { class: "empty", text: "沒有出現在多條規則的身分。" }));
  else {
    var ht = el("table");
    add(ht, el("thead", null, el("tr", null, ["對象", "Tier0", "分數", "最高嚴重度", "相關發現"].map(function (h, i) { return el("th", { class: i === 2 ? "num" : null, text: h }); }))));
    var htb = el("tbody");
    hs.forEach(function (h) {
      add(htb, el("tr", null, el("td", { text: h.label }), el("td", { text: h.tier0 ? "是" : "" }), el("td", { class: "num", text: String(h.score) }),
        el("td", null, sevBadge(h.maxSeverity)),
        el("td", null, h.findings.map(function (fid, i) {
          return [i ? "、" : "", el("a", { href: "#" + fid, text: fid + " " + h.rules[i], onclick: function () { openFinding(fid); } })];
        }))));
    });
    add(ht, htb); add(hc, el("div", { class: "hscroll" }, ht));
  }

  // ---- findings explorer ------------------------------------------------------------------
  var F = D.findings || [], state = { sev: {}, cat: "", q: "" };
  SEV.forEach(function (s) { state.sev[s] = true; });
  var fl = document.getElementById("finding-list"), filt = document.getElementById("filters"), cnt = el("span", { class: "count" });
  var sevBoxes = {};
  SEV.forEach(function (s) {
    var cb = el("input", { type: "checkbox", checked: true, onchange: function () { state.sev[s] = cb.checked; renderFindings(); } });
    sevBoxes[s] = cb;
    add(filt, el("label", null, cb, sevBadge(s)));
  });
  var catSel = el("select", { "aria-label": "類別", onchange: function () { state.cat = catSel.value; renderFindings(); } },
    el("option", { value: "", text: "全部類別" }), CATS.map(function (c) { return el("option", { value: c, text: c }); }));
  var q = el("input", { type: "search", placeholder: "搜尋標題、摘要、規則、對象…", "aria-label": "搜尋", oninput: function () { state.q = q.value.trim().toLowerCase(); renderFindings(); } });
  add(filt, catSel, q, el("button", { class: "toggle", type: "button", text: "全部展開", onclick: function () { fl.querySelectorAll("details").forEach(function (d) { d.open = true; }); } }),
    el("button", { class: "toggle", type: "button", text: "全部收合", onclick: function () { fl.querySelectorAll("details").forEach(function (d) { d.open = false; }); } }), cnt);

  function matches(f) {
    if (!state.sev[f.severity]) return false;
    if (state.cat && f.category !== state.cat) return false;
    if (!state.q) return true;
    var hay = (f.findingId + " " + f.ruleId + " " + f.title + " " + f.summary).toLowerCase();
    if (hay.indexOf(state.q) >= 0) return true;
    return (f.affected || []).some(function (a) { return String(a.label || "").toLowerCase().indexOf(state.q) >= 0 || String(a.id || "").toLowerCase() === state.q; });
  }
  function findingBody(f) {
    var body = el("div", { class: "fbody" }, el("p", { text: f.summary }));
    if ((f.attack || []).length) add(body, el("p", { class: "step-text", text: "ATT&CK：" + f.attack.join(", ") }));
    if ((f.affected || []).length) {
      add(body, el("h4", { text: "受影響對象（" + f.count + "）" }));
      var t = el("table");
      add(t, el("thead", null, el("tr", null, el("th", { text: "對象" }), el("th", { text: "類型" }), el("th", { text: "細節" }))));
      var b = el("tbody");
      f.affected.forEach(function (a) {
        var det = a.detail && a.detail.path ? [pathFromString(a), detailText(Object.assign({}, a.detail, { path: undefined }))] : detailText(a.detail);
        add(b, el("tr", null, el("td", { text: a.label, title: a.id }), el("td", { class: "step-text", text: KIND[a.kind] || a.kind || "" }), el("td", { class: "detail" }, det)));
      });
      add(t, b); add(body, el("div", { class: "scroll" }, t));
      if (f.affectedTruncated) add(body, el("p", { class: "note", text: "另有 " + f.affectedTruncated + " 筆未顯示，完整清單見 findings.json。" }));
    }
    add(body, el("h4", { text: "修補建議" }), el("div", { class: "remed", text: f.remediation || "—" }));
    var ev = f.evidence || {};
    if (Object.keys(ev).length) {
      var dd = el("details", null, el("summary", { class: "step-text", text: "證據（evidence）" }), el("pre", { class: "json", text: JSON.stringify(ev, null, 2) }));
      add(body, el("h4", { text: "證據" }), dd);
    }
    return body;
  }
  function pathFromString(a) {   // PATH-001 rows: draw the route when the entry is in attackPaths
    var e = AP && (AP.entries || []).filter(function (x) { return x.id === a.id; })[0];
    return e ? pathView(e.steps) : el("div", { text: a.detail.path });
  }
  function renderFindings() {
    fl.textContent = "";
    var shownN = 0;
    F.forEach(function (f) {
      if (!matches(f)) return;
      shownN++;
      var d = el("details", { class: "finding", id: f.findingId });
      var built = false;
      d.addEventListener("toggle", function () { if (d.open && !built) { add(d, findingBody(f)); built = true; } });
      add(d, el("summary", null, el("span", { class: "fid", text: f.findingId }), sevBadge(f.severity), el("span", { class: "rid", text: f.ruleId }),
        el("span", { class: "fsum" }, el("span", { class: "ftitle", text: f.title }), el("div", { class: "step-text", text: f.summary.length > 140 ? f.summary.slice(0, 140) + "…" : f.summary })),
        el("span", { class: "num count", text: fmt(f.count) })));
      add(fl, d);
    });
    if (!shownN) add(fl, el("p", { class: "empty", text: "沒有符合條件的發現。" }));
    cnt.textContent = "顯示 " + shownN + " / " + F.length + " 筆";
  }
  function applyFilter(o) {
    SEV.forEach(function (s) { state.sev[s] = !o.sev || s === o.sev; sevBoxes[s].checked = state.sev[s]; });
    state.cat = o.cat || ""; catSel.value = state.cat; state.q = ""; q.value = "";
    renderFindings();
  }
  function openFinding(fid) {
    applyFilter({});
    var d = document.getElementById(fid);
    if (d) { d.open = true; d.scrollIntoView({ block: "start" }); }
  }
  renderFindings();
  if (location.hash && /^#F\d+$/.test(location.hash)) openFinding(location.hash.slice(1));

  // ---- rules ------------------------------------------------------------------------------
  var rc = document.getElementById("rules-card"), R = D.rules || [];
  var skipped = R.filter(function (r) { return r.status === "skipped"; });
  add(rc, el("div", { class: "cardhd" }, el("h3", { text: skipped.length ? "未評估 " + skipped.length + " 條（資料不足）" : "所有規則都有足夠資料可評估" }),
    el("span", { class: "count", text: "共 " + R.length + " 條規則" })));
  var only = el("input", { type: "checkbox", checked: skipped.length > 0, onchange: function () { renderRules(); } });
  add(rc, el("div", { class: "filters" }, el("label", null, only, "只顯示未評估與錯誤")));
  var rtWrap = el("div", { class: "scroll" });
  add(rc, rtWrap);
  function renderRules() {
    rtWrap.textContent = "";
    var t = el("table");
    add(t, el("thead", null, el("tr", null, ["規則", "類別", "標題", "狀態", "發現", "說明"].map(function (h, i) { return el("th", { class: i === 4 ? "num" : null, text: h }); }))));
    var b = el("tbody");
    R.filter(function (r) { return !only.checked || r.status === "skipped" || r.status === "error"; }).forEach(function (r) {
      add(b, el("tr", null, el("td", { class: "rid", text: r.ruleId }), el("td", { text: r.category }), el("td", { text: r.title }),
        el("td", { class: "status st-" + r.status, text: STATUS[r.status] || r.status }), el("td", { class: "num", text: r.findings ? String(r.findings) : "" }),
        el("td", { class: "detail", text: (r.reason || "").split("\n")[0] })));
    });
    add(t, b); add(rtWrap, t);
  }
  renderRules();

  // ---- accepted exceptions ----------------------------------------------------------------
  if ((D.accepted || []).length || (D.exceptionWarnings || []).length) {
    document.getElementById("accepted-sec").hidden = false;
    var ac = document.getElementById("accepted-card"), at = el("table");
    add(at, el("thead", null, el("tr", null, ["規則", "嚴重度", "對象", "理由", "負責人", "到期"].map(function (h) { return el("th", { text: h }); }))));
    var ab = el("tbody");
    (D.accepted || []).forEach(function (a) {
      var x = a.exception || {};
      add(ab, el("tr", null, el("td", { class: "rid", text: a.ruleId }), el("td", null, sevBadge(a.severity)),
        el("td", { text: (a.affected || []).map(function (o) { return o.label; }).join("、") || "（整條規則）" }),
        el("td", { text: x.reason || "" }), el("td", { text: x.owner || "" }), el("td", { text: x.expires || "" })));
    });
    add(at, ab); add(ac, at);
    (D.exceptionWarnings || []).forEach(function (w) { add(ac, el("p", { class: "note", text: "⚠ " + w })); });
  }

  // ---- footer / print ---------------------------------------------------------------------
  add(document.getElementById("foot"), el("p", { text: "本報告含受評環境的組態資訊（帳號已假名化）。僅在 lab 內使用，不上傳到雲端服務、不提交到程式碼庫；假名對照表由資料擁有者保管。" }),
    el("p", { text: "產生：ADHD " + ((D.analyzer || {}).version || "") + "・schema " + (D.schema || "") }));
  window.addEventListener("beforeprint", function () { fl.querySelectorAll("details.finding").forEach(function (d) { d.open = true; }); });
})();
</script>
</body>
</html>
"""
