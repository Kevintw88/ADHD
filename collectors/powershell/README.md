# Collect-ADHD.ps1 — 子公司離線資料收集器

在子公司環境以 **唯讀** 方式收集 AD / Entra ID 混合環境的安全組態，輸出成一個 bundle（JSONL + `manifest.json`），帶回 lab 給地端模型與分析 pipeline 離線使用。

- 只做 LDAP / Microsoft Graph / Event Log 讀取，不修改任何設定、不安裝任何東西到 DC。
- 預設 **假名化**：人名、帳號、UPN、Email 轉成 `u-xxxxxxxxxxxx`；SID、objectId、群組名、主機名保留，攻擊路徑分析仍然可行。
- 每個資料集附 SHA-256 與筆數，lab 端用 `tools/verify_bundle.py` 驗收後才進分析。

---

## 1. 子公司需要準備的東西

| 項目 | 用途 | 備註 |
|---|---|---|
| 一台網域成員的 Windows 主機 | 執行 AD / GPO / ADCS / Entra 模組 | Windows 10/11 或 Server 2016 以上，Windows PowerShell 5.1 或 PowerShell 7 |
| RSAT：Active Directory module | AD、ADACL、ADCS、DCLogs | `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` |
| RSAT：Group Policy Management | GPO | `Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0` |
| `Microsoft.Graph.Authentication` 2.x | Entra、EntraLogs | `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`（只需要這一個模組） |
| 一般網域使用者帳號 | AD 讀取 | 不需要 Domain Admins；FGPP 例外（見限制） |
| 具 **Global Reader** 角色的 Entra 帳號 | Graph delegated 唯讀登入 | 首次使用需管理員同意（見下方） |
| Entra Connect 伺服器的本機系統管理員 | EntraConnect 模組 | 必須在 Entra Connect 主機上執行 |
| 各 DC 的 **Event Log Readers** 成員資格 | DCLogs（選配） | 並開放遠端事件記錄管理（RPC） |

### Graph 權限與管理員同意

腳本以 delegated 方式要求下列唯讀 scope：

```
Directory.Read.All, Policy.Read.All, RoleManagement.Read.Directory, AuditLog.Read.All,
Application.Read.All, UserAuthenticationMethod.Read.All, IdentityRiskyUser.Read.All
(+ IdentityRiskEvent.Read.All，啟用 EntraLogs 時)
```

這些 scope 需要租用戶管理員同意。Global Reader 本身無法同意，所以第一次需要 Global Administrator 或 Privileged Role Administrator 對「Microsoft Graph Command Line Tools」同意一次；或由子公司建立一個只有上述 delegated 權限的 App registration，用 `-GraphClientId` 指定。

### 授權相依的資料

| 資料集 | 需要的授權 | 沒有時的行為 |
|---|---|---|
| `entra_users.signInActivity` | Entra ID P1 | 自動退回，不含最後登入時間（記錄警告） |
| `entra_signins`、`entra_directory_audits` | Entra ID P1 | 資料集標記 `error` |
| `entra_pim_*`、`entra_risky_users`、`entra_risk_detections` | Entra ID P2 | 資料集標記 `error` |

任何單一資料集失敗都不會中斷整體收集，狀態會寫在 manifest 裡。

---

## 2. 執行方式

建議分三次執行，產出的 bundle 在 lab 端以 tenant / domain 合併。三次使用**同一個假名化金鑰**，假名才會一致。

```powershell
# (1) 網域成員主機：AD + Entra（主要的一次）
.\Collect-ADHD.ps1 -Label SubA -TenantId sub-a.onmicrosoft.com

# (2) Entra Connect 伺服器：Windows PowerShell 5.1，以系統管理員執行
#     把 (1) 產生的 ADHD-pseudonym.key 複製過來並指定
.\Collect-ADHD.ps1 -Label SubA-AADC -Include EntraConnect -PseudonymKeyFile .\ADHD-pseudonym.key

# (3) 選配：Entra 紀錄 + DC 安全事件（偵測工程用）
.\Collect-ADHD.ps1 -Label SubA-Logs -Include EntraLogs,DCLogs -LogDays 7 -PseudonymKeyFile .\ADHD-pseudonym.key
```

其他常用參數：

| 參數 | 說明 |
|---|---|
| `-Server dc01.sub-a.local` | 指定查詢的 DC；未指定時固定使用 PDC Emulator |
| `-Credential (Get-Credential)` | AD 查詢用替代認證（GPO 模組與 SYSVOL 掃描不支援） |
| `-FullAcl` | 額外收集所有 user / group / computer 的明確 ACE（資料量大） |
| `-AllGroupMembers` | 收集所有 Entra 群組成員（預設只收可指派角色、有角色指派或被 CA 引用的群組） |
| `-UseDeviceCode` | Graph 改用裝置代碼登入（伺服器沒有瀏覽器時） |
| `-SkipGpoXml` | 不輸出 GPO XML 報表 |
| `-NoPseudonymize` | 關閉假名化，僅限已取得資料擁有者同意 |
| `-NoZip` | 不壓縮 |

多網域 forest：每個網域以 `-Server` 指向該網域的 DC 各跑一次。

---

## 3. 輸出

```
<OutputRoot>\
├── ADHD-pseudonym.key                        ← 假名化金鑰：留在子公司
├── ADHD-pseudonym-map-<bundle>.csv           ← 假名 → 原值對照表：留在子公司
├── ADHD-Collect-SubA-20261013T010203Z\       ← bundle
│   ├── manifest.json
│   ├── collection.log
│   ├── ad_users.jsonl  ...                   ← 每個資料集一個 JSONL（一行一筆，UTF-8）
│   ├── gpo_reports\{guid}.xml
│   └── entraconnect_config\...
├── ADHD-Collect-SubA-20261013T010203Z.zip    ← 帶回 lab 的就是這個
└── ADHD-Collect-SubA-20261013T010203Z.zip.sha256
```

所有時間皆為 UTC ISO-8601；TimeSpan 以秒表示；`manifest.json` 記錄 schema（`adhd.collect/1`）、執行環境、參數、每個資料集的狀態 / 筆數 / SHA-256。

### 資料集（data contract）

| 模組 | 資料集 | 內容重點 |
|---|---|---|
| AD | `ad_forest` | 功能等級、網域、GC、站台、UPN 尾碼、schema 版本、Optional features |
| | `ad_domain` | MachineAccountQuota、dSHeuristics、krbtgt 密碼最後變更、LAPS / 2016 schema 是否存在 |
| | `ad_password_policies` | 預設網域密碼原則、FGPP |
| | `ad_trusts` | 方向、類型、SID filtering、選擇性驗證、TGT delegation、加密類型 |
| | `ad_domain_controllers` | OS、站台、GC / RODC、FSMO |
| | `ad_ous` | OU 與 domain root 的 gPLink（啟用 / 強制 / 順序）、封鎖繼承 |
| | `ad_users` | UAC 旗標、SPN、委派（約束 / RBCD）、sIDHistory、adminCount、密碼 / 登入時間、KeyCredentialLink 數量、description 密碼提示旗標 |
| | `ad_computers` | 同上 + DC 判斷、LAPS 到期時間（只收到期時間，不收密碼） |
| | `ad_service_accounts` | gMSA / sMSA、可讀取密碼的主體（SID） |
| | `ad_groups` | 群組成員（已解析成 SID；FSP 解析為外部 SID；無法解析保留 `DN:`） |
| ADACL | `ad_guid_map` | schemaIDGUID / extended right GUID → 名稱 |
| | `ad_acls` | 高價值物件的 owner 與明確 ACE（principal 以 SID 表示，objectType 已解析名稱）；`reason` 說明為何收集 |
| GPO | `ad_gpos` | GPO 清單、狀態、版本、WMI filter |
| | `gpo_reports/` | 每個 GPO 的 XML 報表（帳號與 email 已假名化） |
| | `gpo_gpp_cpassword` | SYSVOL 中含 `cpassword` 的 GPP 檔案路徑與次數（**不收值**） |
| ADCS | `adcs_containers` | PKI 容器 ACL、NTAuth 憑證數 |
| | `adcs_cas` | Enterprise CA、發佈的範本、CA 物件 ACL |
| | `adcs_templates` | 範本旗標（ESC1/2/3/9 相關衍生欄位）、EKU、核准 / 簽章需求、ACL |
| EntraConnect | `entraconnect_server` | 產品版本、ADSync 服務帳號、本機 Administrators / ADSyncAdmins |
| | `entraconnect_scheduler` / `entraconnect_features` | Staging mode、同步週期、PHS / writeback 功能 |
| | `entraconnect_connectors` | Connector 參數（排除密碼類參數）、分割區與 OU 篩選、PHS 啟用狀態 |
| | `entraconnect_config/` | `Get-ADSyncServerConfiguration` 匯出（同步規則等） |
| Entra | `entra_organization`、`entra_domains` | 租用戶、驗證網域（Managed / Federated） |
| | `entra_users` | 帳號狀態、類型、同步屬性（含 `onPremisesSecurityIdentifier` 可對應 AD SID）、signInActivity |
| | `entra_groups`、`entra_group_memberships` | 群組屬性、可指派角色；指定群組的遞移成員與 owner |
| | `entra_role_definitions`、`entra_role_assignments` | 目錄角色定義與指派 |
| | `entra_pim_eligibility`、`entra_pim_assignments` | PIM 合格 / 啟用排程 |
| | `entra_admin_units`、`entra_admin_unit_roles` | 管理單位與範圍角色 |
| | `entra_ca_policies`、`entra_named_locations` | 條件式存取 |
| | `entra_authorization_policy`、`entra_security_defaults`、`entra_auth_methods_policy` | 使用者同意、來賓權限、Security Defaults、驗證方法原則 |
| | `entra_user_registration` | MFA 註冊狀態、是否為管理員 |
| | `entra_devices` | 裝置信任類型、合規、最後登入 |
| | `entra_applications`、`entra_application_owners` | App 權限需求、credential（只收 keyId 與到期日）、owner |
| | `entra_service_principals`、`entra_sp_owners` | SP 類型、擁有租戶、credential、owner |
| | `entra_app_role_assignments` | 應用程式權限授予（租戶 App 與 Managed Identity） |
| | `entra_oauth2_grants` | Delegated 權限同意 |
| | `entra_permission_catalog` | 被引用資源的 appRole / scope 對照（id → 權限名稱） |
| | `entra_risky_users` | Identity Protection 風險使用者 |
| EntraLogs | `entra_signins`、`entra_directory_audits`、`entra_risk_detections` | 近 `-LogDays` 天，上限 `-MaxLogRecords` 筆 |
| DCLogs | `dc_security_events` | 指定事件 ID，每台 DC 每個 ID 上限 `-MaxEventsPerId` 筆，EventData 解析為欄位 |

### 絕對不收集

密碼雜湊、`NTDS.dit`、DCSync 輸出、LAPS 密碼（`ms-Mcs-AdmPwd`、`msLAPS-*Password`）、BitLocker 復原金鑰、TPM owner 資訊、gMSA 密碼（`msDS-ManagedPassword`）、App secret / 憑證私鑰 / secret hint、GPP `cpassword` 值、Connector 密碼參數。

實作上有兩道防線：(1) 每個查詢都明確列出要讀的屬性，不使用 `-Properties *`；(2) 序列化時任何層級出現禁止欄位名稱都會被丟棄。

---

## 4. 假名化

- 演算法：`HMAC-SHA256(key, lowercase(value))` 取前 48 bits，前綴 `u-`；email 形式保留 `@domain`（例如 `u-3fa2c1d9e0b4@sub-a.com`）。
- 處理範圍：AD / Entra 使用者的帳號、UPN、姓名、顯示名稱、email；以及這些值出現在其他資料集（DN 第一段、`DOMAIN\帳號`、紀錄、GPO XML）時。
- 不假名化：SID、objectId、群組 / 電腦 / OU / GPO / App 名稱、內建帳號（RID < 1000，例如 Administrator、krbtgt）、同步基礎設施帳號（`MSOL_*`、`Sync_*`、`AZUREADSSOACC`、`provAgentgMSA`）。
- 金鑰檔存在就沿用，因此同一子公司不同次的收集可以互相比對。`manifest.json` 只記錄金鑰指紋（`keyId`），不含金鑰。
- 金鑰與對照表寫在 bundle 資料夾**之外**；lab 端驗收時若在 bundle 內發現它們會直接判定失敗。

---

## 5. 帶回 lab 後

```bash
python3 tools/verify_bundle.py ADHD-Collect-SubA-20261013T010203Z.zip
python3 tools/verify_bundle.py ADHD-Collect-SubA-20261013T010203Z.zip --strict --json intake-report.json
python3 tools/verify_bundle.py ADHD-Collect-SubA*.zip --json intake-report.json      # 一次驗同一輪的多份 bundle
python3 tools/bundle_sanity.py ADHD-Collect-SubA*.zip --json sanity-report.json      # 驗收通過後的語意檢查
```

檢查項目：manifest schema、每個檔案的 SHA-256 與筆數、每行 JSON 合法、禁止欄位、`cpassword` 值與私鑰區塊、金鑰 / 對照表是否被帶出、未假名化的 email。結束碼 0 = 全部通過、1 = 任一份失敗、2 = 參數錯誤。

---

## 6. 已知限制

- **FGPP**：Password Settings Container 預設只有 Domain Admins 可讀，一般帳號讀不到時只會記錄警告。
- **msDS-KeyCredentialLink**：非特權帳號可能讀不到內容，`keyCredentialLinkCount` 為 0 不代表一定沒有 shadow credentials。
- **GPO / SYSVOL**：GroupPolicy 模組不支援 `-Credential`，會使用目前登入身分。
- **假名化覆蓋率**：只對「已收集到的使用者」的識別值做精確比對，再加上 email 樣式比對。沒有出現在 AD / Entra 使用者清單中的姓名（例如外部人員的顯示名稱）可能保留原文。單獨執行 EntraConnect 模組時（0.1.2 起），本機 Administrators / ADSyncAdmins 的使用者成員、ADSync 服務帳號與 connector 登入帳號會被登錄並假名化，`entraconnect_config/` 的文字檔也會套用；同一把金鑰下，假名與 AD bundle 一致。0.1.1 以前單獨收集的 AADC bundle 可能含上述帳號明文。
- **CA 伺服器層級設定**（`EDITF_ATTRIBUTESUBJECTALTNAME2`、CA 本身的權限、Web Enrollment）存在 CA 主機登錄機碼，本版未收集；ESC6/7/8 需另行確認。
- **PowerShell 語言模式**：需要 FullLanguage；在 AppLocker / WDAC 強制 Constrained Language Mode 的主機上無法執行。
- 首次執行會被 EDR 視為大量 LDAP 查詢，建議事先通知子公司 SOC。

---

## 7. 測試

`tests/powershell/Invoke-CollectorSmokeTest.ps1` 以 mock 取代 AD、GroupPolicy、ADSync、Graph 與 `Get-WinEvent`，端對端執行全部模組，並驗證輸出格式、群組成員解析、ACL GUID 解析、ESC 旗標、Graph 分頁、假名化與禁止欄位過濾。可在任何平台的 PowerShell 7 執行：

```bash
pwsh -NoProfile -File tests/powershell/Invoke-CollectorSmokeTest.ps1
```

真實環境驗證請先在 lab AD / 測試租用戶跑一次，再交給子公司。
