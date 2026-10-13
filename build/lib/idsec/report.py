"""確定性 Markdown 報告（不經 LLM，數字與名稱全部來自工具結果）。"""

from __future__ import annotations

from .models import utcnow
from .pipeline import EntityResult

MODULE_TITLES = {
    "discovery": "環境盤點與指紋",
    "assess_ad": "AD 組態評估",
    "assess_adcs": "AD CS 評估",
    "assess_entra": "Entra / M365 組態評估",
    "paths_ad": "地端 AD 攻擊路徑",
    "paths_entra": "Entra 攻擊路徑",
    "detect_mdi_triage": "MDI 告警 AI 分流（Phase 2）",
    "detect_sigma_dc": "DC 事件 + Sigma 偵測（Phase 2）",
    "detect_entra_signin": "Entra 登入風險分流（Phase 2）",
}


def _t(mid: str) -> str:
    return MODULE_TITLES.get(mid, mid)


def render_markdown(r: EntityResult) -> str:
    fp, cap = r.fingerprint, r.capability
    ad, hy, idn, svc, tl, tm = fp.ad, fp.hybrid, fp.identity, fp.services, fp.tooling, fp.telemetry
    L: list[str] = []
    L += [f"# {r.name} 身分安全評估報告", "",
          f"產生時間：{utcnow()}　法人代號：`{r.entity}`　Profile：**{cap.profile} {cap.profile_name}**", ""]

    if r.paths:
        p = r.paths
        pct = round(p.sources_with_path / p.sources_total * 100, 1) if p.sources_total else 0
        L += ["## 重點", "",
              f"- {p.sources_with_path} / {p.sources_total} 個非特權帳號（{pct}%）存在通往 Tier 0 的攻擊路徑。"]
        if p.choke_points:
            c = p.choke_points[0]
            L.append(f"- 最有效的單一修補：移除 `{p.name(c.edge.src)}` -[{c.edge.kind}]-> `{p.name(c.edge.dst)}`，"
                     f"可切斷 {c.sources_cut} 個來源（{c.sources_cut_pct}%）。")
        if r.findings:
            L.append(f"- 評估工具共 {len(r.findings)} 項發現，最高優先：{r.findings[0].id}（{r.findings[0].priority_reason}）。")
        L.append(f"- 遙測覆蓋分數 {tm['coverage_score']}，缺口 {len(cap.gaps)} 項。")
        L.append("")

    L += ["## 環境指紋", "",
          "| 項目 | 值 |", "| --- | --- |",
          f"| Forest / 網域數 | {ad['forest']} / {ad['domains']} |",
          f"| DC 數量 / 作業系統 | {ad['dc_count']} / {', '.join(f'{k}×{v}' for k, v in ad['dc_os'].items())} |",
          f"| 功能等級 | {', '.join(ad['functional_levels']) or '未知'} |",
          f"| 信任關係（未啟用 SID Filtering） | {ad['trusts']}（{ad['trusts_without_sid_filtering']}） |",
          f"| Entra 租戶 / 同步工具 / 驗證方式 | {'有' if hy['tenant_present'] else '無'} / {hy['sync_tool']} / {hy['auth_method']} |",
          f"| Seamless SSO | {'是' if hy['seamless_sso'] else '否'} |",
          f"| 啟用使用者 / 特權帳號 | {idn['users_enabled']} / {idn['privileged_enabled']} |",
          f"| 可 Kerberoast（其中特權） | {idn['kerberoastable']}（{idn['kerberoastable_privileged']}） |",
          f"| AS-REP Roast / 非 DC 無限制委派 | {idn['asrep_roastable']} / {idn['unconstrained_delegation_non_dc']} |",
          f"| 90 天未登入仍啟用 | {idn['stale_enabled']} |",
          f"| gMSA 數量 | {idn['gmsa']} |",
          f"| AD CS（ESC1 候選範本） | {'有' if svc['adcs_present'] else '無'}（{', '.join(svc['esc1_candidates']) or '無'}） |",
          f"| MDI / EDR / SIEM | {'有' if tl['mdi'] else '無'} / {tl['edr'] or '無'} / {tl['siem'] or '無'} |",
          f"| 稽核原則達成 / Sysmon 覆蓋 | {tm['audit_ratio']} / {tm['sysmon_coverage'] if tm['sysmon_coverage'] is not None else '未知'} |",
          ""]

    L += ["## 能力矩陣判定", "", "| 模組 | 狀態 |", "| --- | --- |"]
    for m in cap.enabled_modules:
        L.append(f"| {_t(m)} | 啟用 |")
    for m, why in cap.disabled_modules.items():
        L.append(f"| {_t(m)} | 未啟用：{why} |")
    L.append("")
    if cap.tier0_extra:
        L += ["混合環境額外列入 Tier 0：", ""] + [f"- {x}" for x in cap.tier0_extra] + [""]

    if cap.gaps:
        L += ["## 缺口報告", "", "| 代號 | 缺口 | 影響模組 | 建議 |", "| --- | --- | --- | --- |"]
        for g in cap.gaps:
            L.append(f"| {g.id} | {g.title} | {', '.join(_t(b) for b in g.blocks) or '—'} | {g.remediation} |")
        L.append("")

    if r.paths:
        p = r.paths
        L += ["## 攻擊路徑", ""]
        if p.choke_points:
            L += ["### 建議修補順序（每步實際移除後重算）", "",
                  "| 順序 | 移除的邊 | 本步切斷來源 | 佔比 | 修補後仍有路徑 |", "| --- | --- | --- | --- | --- |"]
            for i, c in enumerate(p.choke_points, 1):
                L.append(f"| {i} | `{p.name(c.edge.src)}` -[{c.edge.kind}]-> `{p.name(c.edge.dst)}` | "
                         f"{c.sources_cut} | {c.sources_cut_pct}% | {c.remaining_after} |")
            L.append("")
        if p.sample_paths:
            L += ["### 代表路徑", ""]
            for i, ap in enumerate(p.sample_paths, 1):
                L.append(f"{i}. （{ap.shared_by} 個來源共用）`{p.describe(ap)}`")
            L.append("")

    if r.findings:
        L += ["## 評估發現（依優先序）", "", "| 優先分數 | 來源 | 代號 | 嚴重度 | 說明 | 排序理由 |",
              "| --- | --- | --- | --- | --- | --- |"]
        for f in r.findings[:20]:
            L.append(f"| {f.priority} | {f.source} | {f.id} | {f.severity} | {f.title} | {f.priority_reason} |")
        L.append("")

    L += ["---", "本報告由確定性流程產生，未經 LLM 改寫。修補動作須經人工審核閘門。", ""]
    return "\n".join(L)
