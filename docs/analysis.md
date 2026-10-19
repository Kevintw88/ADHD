# 離線分析（Phase 1）

把同一輪收集的 bundle（網域主機 + Entra Connect 伺服器 + 選配的 Logs）載入成一張 AD / Entra 混合關聯圖，跑確定性規則，輸出給人看的報告、給地端模型用的 JSON，以及可查詢的 SQLite。

- 只用 Python 標準函式庫（3.8 以上），隔離的分析主機不需要安裝任何套件。
- 所有「幾天前」的判斷都以 bundle 的**收集完成時間**為基準，同一份資料任何時候重跑結果都相同。
- 規則宣告自己需要的資料集；資料沒收到或收集失敗時，規則標為「略過」並寫明原因，不會當成「通過」。

## 使用方式

```bash
cd ~/adhd && git pull

# 1. 驗收（必做）
python3 tools/verify_bundle.py /srv/adhd/intake/ADHD-Collect-SubA*20261015*.zip
python3 tools/bundle_sanity.py /srv/adhd/intake/ADHD-Collect-SubA*20261015*.zip

# 2. 分析（同一輪的 bundle 一起丟進去）
python3 tools/analyze.py /srv/adhd/intake/ADHD-Collect-SubA*20261015*.zip --out /srv/adhd/reports/SubA-20261015

# 其他
python3 tools/analyze.py --list-rules              # 規則目錄（docs/rules.md 同內容）
python3 tools/analyze.py ... --only AD-020 ADCS    # 只跑指定規則 / 類別
```

不同假名化金鑰的 bundle 預設拒絕一起分析（假名對不上會產生錯誤結論）；確定要混用時加 `--allow-mixed-keys`。

## 輸出

| 檔案 | 給誰 | 內容 |
|---|---|---|
| `findings.md` | 人 | 摘要、依嚴重度排序的發現（對象、細節、修補建議、ATT&CK）、每條規則的執行狀態 |
| `findings.json` | 地端模型 / 自動化 | schema `adhd.findings/1`：`summary`、`rules[]`（狀態與略過原因）、`findings[]`（含 `affected[]` 與 `evidence`） |
| `graph.sqlite` | 查詢 / 之後的 MCP 工具 | `nodes`、`edges`、`findings`、`affected`、`rules`、`meta` |

帳號名稱沿用收集時的假名（`u-xxxxxxxxxxxx`），報告可以安全地在 lab 內流通；需要還原時由子公司以對照表查詢。輸出含環境資料，`.gitignore` 已排除，不要提交到 repo。

## 關聯圖

| 節點 id | 類型 |
|---|---|
| SID | AD user / computer / group / gMSA / 外部主體；網域物件使用網域 SID |
| `dn:<小寫 DN>` | OU、container、CA、憑證範本、無法解析的 DN 成員 |
| `gpo:<guid>` | GPO |
| `entra:<objectId>` | Entra 使用者、群組、服務主體、App 註冊 |
| `entra-role:<roleDefinitionId>` | Entra 目錄角色 |

主要的邊：`MemberOf`（含 primary group）、`Contains`、`GPLink`、ACL 權限（`GenericAll`、`GenericWrite`、`WriteDacl`、`WriteOwner`、`Owns`、`WriteAllProperties`、`AllExtendedRights`、`ForceChangePassword`、`AddMember`、`AddSelf`、`WriteSPN`、`AddKeyCredentialLink`、`WriteRBCD`、`WriteGPLink`、`ReadLAPSPassword`、`Enroll`）、`DCSync`（同時具 Get-Changes 與 Get-Changes-All，或 domain root 的 GenericAll / AllExtendedRights）、`ReadGMSAPassword`、`AllowedToDelegate`、`AllowedToAct`、`SyncedTo`（AD → Entra，依 `onPremisesSecurityIdentifier`）、`EntraMemberOf`、`HasRole`、`AppRole`、`OAuthGrant`、`AppIdentity`、`Publishes`。

只對應「能取得控制權或密碼」的權限；讀取權與範圍很窄的寫入（userCertificate、terminalServer 等）不建邊，所以 Windows 的預設 ACL 不會產生雜訊。

### Tier0 的定義

Domain Admins、Enterprise Admins、Schema Admins、Administrators、Domain Controllers、（Enterprise）Read-only DCs、Key Admins、Enterprise Key Admins、Account / Server / Print / Backup Operators、DnsAdmins，加上這些群組的**遞移成員**、所有 DC、krbtgt，以及**所有具 DCSync 權限的主體**（例如 Entra Connect 的 connector 帳號）。

## 規則

約 60 條，分 AD、ADCS、Entra、Hybrid 四類，完整清單見 [rules.md](rules.md)。每條規則的狀態：

| 狀態 | 意義 |
|---|---|
| 有發現 | 至少一筆發現 |
| 通過 | 資料完整且沒有發現 |
| 略過 | 需要的資料集沒收到或收集失敗（原因寫在報告最後的狀態表） |
| 錯誤 | 規則執行例外（不影響其他規則；請回報） |

## SQLite 查詢範例

```sql
-- 誰能 DCSync
SELECT n.label, n.kind FROM edges e JOIN nodes n ON n.id = e.src WHERE e.kind = 'DCSync';

-- 非 Tier0 主體對 Tier0 物件的控制權限
SELECT s.label AS principal, e.kind, d.label AS target
FROM edges e JOIN nodes s ON s.id = e.src JOIN nodes d ON d.id = e.dst
WHERE d.tier0 = 1 AND s.tier0 = 0
  AND e.kind IN ('GenericAll','GenericWrite','WriteDacl','WriteOwner','Owns','ForceChangePassword','AddMember');

-- 某條發現影響的對象
SELECT label, detail FROM affected WHERE finding_id = 'F001';
```

## 給地端模型的介面

地端模型（qwen / glm）讀 `findings.json`，不直接讀原始資料：發現已經是確定性規則的結果並附證據，模型負責排序、說明與修補建議的在地化，不負責「判斷有沒有問題」。建議提示詞要求模型：

1. 只根據 `findings[]` 與 `evidence` 陳述事實，不推測沒有出現在資料中的內容；
2. 引用 `findingId` 與 `ruleId`；
3. `rules[]` 中狀態為「略過」的項目明確列為「未評估」，不可寫成「沒有問題」。

## 已知限制

- ACL 只收集高價值物件（domain root、AdminSDHolder、OU、adminCount=1、GPO、DC、同步帳號、特定群組）；一般帳號之間的委派權限需要收集時加 `-FullAcl`。
- Entra 角色未區分管理單位（AU）範圍的指派，AU 範圍的角色也會被當作特權。
- 條件式存取只判斷「是否套用所有使用者 / 管理員角色 + 所有雲端應用程式」，未評估位置、平台、裝置等條件造成的缺口。
- ADCS 只評估 AD 中的範本與 CA 物件（ESC1–5、ESC9）；ESC6 / 7 / 8 / 11 需在 CA 主機上檢查。
- 攻擊路徑（多跳的最短路徑）是 Phase 1 第 3 步，尚未實作；目前規則只看單跳的權限。

## 測試

```bash
python3 -m unittest discover -s tests/python -v
```

`tests/python/fixtures.py` 產生兩套合成環境（收集器的實際檔案格式）：「脆弱」環境為每條規則都埋了至少一個弱點，測試確認每條規則都觸發且嚴重度正確；「乾淨」環境確認沒有任何非資訊類的誤報。要同時跑真實收集器輸出的整合測試，把 `tests/powershell/Invoke-CollectorSmokeTest.ps1` 產生的 zip 指給 `ADHD_SMOKE_BUNDLES`（以 `:` 分隔）。
