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

# 攻擊路徑查詢
python3 tools/paths.py /srv/adhd/intake/ADHD-Collect-SubA*20261015*.zip                  # 起點與優先切斷的步驟
python3 tools/paths.py ... --from u-3b6a98551f47                                        # 某個主體到 Tier0 的最短路徑
python3 tools/paths.py ... --to CA-TWCA-01                                              # 誰能取得某個物件

# 其他
python3 tools/analyze.py --list-rules              # 規則目錄（docs/rules.md 同內容）
python3 tools/analyze.py ... --only AD-020 ADCS    # 只跑指定規則 / 類別
```

不同假名化金鑰的 bundle 預設拒絕一起分析（假名對不上會產生錯誤結論）；確定要混用時加 `--allow-mixed-keys`。

補收的 bundle 可以和原本那輪一起丟進去：同一個資料集若同時出現在兩份 bundle、而且來源相同（同一個 AD 網域、同一個租用戶、同一台 Entra Connect 伺服器），只採用收集完成時間較新的那份，並在執行時與 `findings.json` 的 `bundles[].supersededDatasets` 註明；來源不同（例如另一個網域、第二台 Entra Connect）則合併。

## 輸出

| 檔案 | 給誰 | 內容 |
|---|---|---|
| `findings.md` | 人 | 摘要、依嚴重度排序的發現（對象、細節、修補建議、ATT&CK）、每條規則的執行狀態 |
| `findings.json` | 地端模型 / 自動化 | schema `adhd.findings/1`：`summary`、`rules[]`（狀態與略過原因）、`findings[]`（含 `affected[]` 與 `evidence`） |
| `graph.sqlite` | 查詢 / MCP 伺服器 | `nodes`、`edges`、`findings`、`affected`、`rules`、`meta`，以及攻擊路徑的 `attack_paths`、`attack_steps`、`attack_targets` |

帳號名稱沿用收集時的假名（`u-xxxxxxxxxxxx`），報告可以安全地在 lab 內流通；需要還原時由子公司以對照表查詢。輸出含環境資料，`.gitignore` 已排除，不要提交到 repo。

## 重點對象（跨規則關聯）

報告會把同一個身分在不同規則的發現合併計分（嚴重 10、高 5、中 2、低 1；資訊類不計），列在摘要之後：

- AD 帳號與它同步到 Entra 的帳號視為同一身分（依 `onPremisesSecurityIdentifier`）；
- App 註冊與它的服務主體視為同一身分；
- 條件式存取原則的「排除對象」也會計入（標示為「排除對象」）。

單條規則看起來只是「中」的問題，疊在同一個 Tier0 帳號上時往往才是最該先處理的。`findings.json` 的 `hotspots[]` 提供同樣的資料給地端模型。

## 已確認例外

審查後確認可接受的項目（例如緊急存取帳號），寫進例外檔，分析時加上 `--exceptions`：

```bash
python3 tools/analyze.py ... --out ... --exceptions /srv/adhd/exceptions/SubA.json
```

格式見 [exceptions.example.json](exceptions.example.json)：`id` 是 findings.json 中 `affected[].id`（SID、`entra:<objectId>` 等），`*` 代表整條規則；`reason` 必填；`expires` 到期後自動失效並在報告中提醒。被接受的項目從發現中移出，改列在報告末的「已接受的例外」；比對不到任何發現的例外也會提醒（可能已修正，可以移除）。例外檔含環境識別資訊，和報告一樣存放在 lab，不進 repo。

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

66 條，分 AD、ADCS、Entra、Hybrid、Path 五類，完整清單見 [rules.md](rules.md)。每條規則的狀態：

| 狀態 | 意義 |
|---|---|
| 有發現 | 至少一筆發現 |
| 通過 | 資料完整且沒有發現 |
| 略過 | 需要的資料集沒收到或收集失敗（原因寫在報告最後的狀態表） |
| 錯誤 | 規則執行例外（不影響其他規則；請回報） |

## 攻擊路徑

PATH-001 / PATH-002 把關聯圖上的事實串成「誰取得 A 就能接管 B」的攻擊步驟，從所有 Tier0 資產反向計算每個主體的最短路徑（成員關係不計步數，各步驟有成本，例如重設密碼 1、資源型委派 1.5、定向 Kerberoasting 2）。實作在 `adhd/paths.py`。

| 步驟來源 | 說明 |
|---|---|
| 群組 / 角色成員 | AD 群組、Entra 群組、Entra 角色；Everyone 與 Authenticated Users 視為所有啟用帳號的隱含成員 |
| ACL 權限 | 只採用對該類物件真的能取得控制的權限（使用者：重設密碼、Key Credential、SPN…；群組：新增成員；電腦：LAPS、RBCD…） |
| 可繼承的 ACE | OU / 容器上會被繼承的 ACE，展開到符合 inheritedObjectType 的後代物件；遇到受保護的 DACL 或 adminCount=1 的物件停止 |
| 容器控制 | 對 OU 有 GenericAll / WriteDacl / WriteOwner / Owns，可加入可繼承權限，取得其下所有未受保護的物件 |
| GPO | 能修改 GPO 即取得它套用到的使用者與電腦（考慮停用的連結、封鎖繼承與強制） |
| AdminSDHolder | 能修改 AdminSDHolder 即取得所有 adminCount=1 的物件 |
| 委派 | 資源型限制委派、限制委派（含 / 不含協定轉換） |
| Entra Connect | 伺服器的本機管理員 → 伺服器 → 保存在其上的 AD DS connector 帳號 |
| ADCS | 已發佈 ESC1 範本的申請權、已發佈範本的修改權（ESC4）→ 網域；企業 CA 主機視同 Tier0 |
| 混合 | AD 帳號 → 由它同步的 Entra 帳號；Entra 群組 / App / 服務主體的擁有者 |

Tier0 目標：AD Tier0（見上）、網域物件、Entra Tier0 角色與持有者、持有可提權應用程式權限的服務主體，以及 Entra Connect 伺服器與企業 CA 主機。

- **起點**：實際持有第一個可濫用權限的主體（不是先經過成員關係的帳號）；經過廣泛群組的路徑只列在該廣泛群組下。
- **影響帳號（exposedAccounts）**：最短路徑以這個起點開始的啟用帳號數（透過群組成員關係共用）。
- **優先切斷（PATH-002）**：最多帳號的最短路徑都經過的步驟。
- 每個主體只算最短的一條；切斷後可能仍有較長的替代路徑，處理後要重新分析確認。

`findings.json` 的 `attackPaths`（前 100 個起點，含每一步的 id）與 `graph.sqlite` 的 `attack_paths` 表提供同樣的資料給地端模型與 [MCP 伺服器](mcp.md)；`tools/paths.py` 可以查單一主體的路徑（`--from`）或誰能取得某個物件（`--to`）。

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

-- 影響最多帳號的攻擊路徑
SELECT entry_label, hops, exposed_accounts, path FROM attack_paths ORDER BY broad DESC, exposed_accounts DESC LIMIT 10;
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
- 攻擊路徑只用收集到的資料：沒有工作階段（誰登入哪台主機）與一般主機的本機管理員資料，所以「登入過的主機被入侵」這類路徑不會出現；Entra 端未包含角色之間的管理關係（例如 Privileged Authentication Administrator 可重設 GA 的驗證方式）。

## 測試

```bash
python3 -m unittest discover -s tests/python -v
```

`tests/python/fixtures.py` 產生兩套合成環境（收集器的實際檔案格式）：「脆弱」環境為每條規則都埋了至少一個弱點，測試確認每條規則都觸發且嚴重度正確；「乾淨」環境確認沒有任何非資訊類的誤報。要同時跑真實收集器輸出的整合測試，把 `tests/powershell/Invoke-CollectorSmokeTest.ps1` 產生的 zip 指給 `ADHD_SMOKE_BUNDLES`（以 `:` 分隔）。
