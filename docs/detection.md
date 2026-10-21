# 偵測工程（Phase 2）

把攻擊手法寫成 **Sigma** 規則（中立格式，可轉成 Sentinel KQL、Splunk SPL、Elastic 等），在 lab 以合成事件與錄製事件**重放驗證**，再用姿態分析的結果把規則**調校成符合各公司環境**的版本。只用 Python 標準函式庫。

```
detections/sigma/*.yml ──┬─ selftest：detections/tests 的合成事件重放（每條規則都有會觸發與不該觸發的案例）
                         ├─ run：bundle 內收集到的事件 / lab 錄製的事件 → 告警 + 涵蓋範圍
                         │        ↑ 環境資料（Tier0、DC、Entra Connect connector）與攻擊路徑來自同一輪的姿態分析
                         └─ tune：把占位符換成該環境的 SID / 主機名稱 → 交給 sigma-cli / pySigma 轉成 SIEM 查詢
```

規則目錄見 [detection-rules.md](detection-rules.md)。

## 使用

```bash
cd ~/adhd && git pull

python3 tools/detect.py selftest     # 重放全部測試案例（改規則後必跑）
python3 tools/detect.py lint         # 規則必要欄位、ATT&CK 標籤、每條規則都有會觸發的測試

# 對一輪收集的事件執行（需要收集時包含 DCLogs / EntraLogs / SecurityAlerts）
python3 tools/detect.py run /srv/adhd/intake/ADHD-Collect-SubA*20261020*.zip --out /srv/adhd/reports/SubA-20261020

# 重放 lab 錄製的事件（JSONL；收集器 dc_security_events 的格式或已攤平的 Sigma 欄位都可以），
# 環境資料取自同一個 bundle
python3 tools/detect.py run <bundles> --events windows/security=lab-attack.jsonl --out ...

# 產生調校後的規則
python3 tools/detect.py tune /srv/adhd/intake/ADHD-Collect-SubA*20261020*.zip --out /srv/adhd/tuned/SubA
```

輸出 `detections.md`（給人看）與 `detections.json`（schema `adhd.detections/1`）：告警、涉及的對象與姿態背景、涵蓋範圍。

## 事件來源與欄位

| logsource | 資料集（收集器模組） | 欄位名稱 |
|---|---|---|
| `windows/security` | `dc_security_events`（DCLogs） | Windows 事件標準欄位：`EventID`、`TargetUserName`、`SubjectUserSid`、`ServiceName`… |
| `azure/signinlogs` | `entra_signins`（EntraLogs） | Microsoft Graph signIn 欄位，巢狀以點號：`status.errorCode`、`clientAppUsed`、`deviceDetail.isCompliant`… |
| `azure/auditlogs` | `entra_directory_audits`（EntraLogs） | Graph directoryAudit：`activityDisplayName`、`targetResources.modifiedProperties.newValue`… |
| `m365defender/alerts` | `security_alerts`（SecurityAlerts，新增） | Graph security alert（alerts_v2）：`serviceSource`、`severity`、`evidence.userAccount.userSid`、`evidence.deviceDnsName`… |

Azure 類規則使用 Graph 的欄位名稱；轉成 Sentinel（`SigninLogs`、`AuditLogs` 資料表）時需要欄位對應（例如 `status.errorCode` → `ResultType`）。Windows 規則使用標準欄位，可直接以 pySigma 的 Windows pipeline 轉換。

收集器新增 **SecurityAlerts** 模組（Graph `security/alerts_v2`，唯讀，需要 `SecurityAlert.Read.All` 與 Security Reader 以上角色），只保留偵測與關聯需要的欄位：帳號名稱與 UPN 假名化、SID 與主機名稱保留、告警標題中的帳號與顯示名稱換成假名，`description` 等自由文字不收集。

## 環境資料（占位符）

規則以 Sigma 的 `|expand` 占位符表示「這個環境才知道的值」，由同一輪的姿態分析提供：

| 占位符 | 內容 | 用在 |
|---|---|---|
| `%dcsync_expected%` | DC、Entra Connect connector、MSOL_ 帳號的 SID | DCSync 排除預期的複寫 |
| `%keycred_writers%` | connector / MSOL_ 帳號的 SID | Shadow Credentials 排除 Windows Hello 金鑰寫入 |
| `%tier0_groups%` | 本環境的 Tier0 群組 SID | Tier0 群組成員異動 |
| `%tier0_accounts%` | Tier0 帳號 SID | RC4 申請 Tier0 SPN、Tier0 密碼被重設、MDI 告警涉及 Tier0 |
| `%entra_tier0_users%` | 持有 Entra Tier0 角色的使用者 objectId | Tier0 雲端管理員從未受管理的裝置登入 |
| `%tier0_hosts%` | DC、Entra Connect、企業 CA 主機名稱 | Defender 告警涉及 Tier0 主機 |

占位符沒有值時：作為排除條件就不套用（告警變多），作為選取條件就不會觸發（涵蓋範圍會標示「缺環境資料」）。`tune` 產生的規則只放 SID、objectId 與主機名稱，不受假名化影響，可以直接部署；同時輸出 `environment.json`，也能交給 pySigma 的占位符 pipeline 使用。

轉成 SIEM 查詢（在可安裝套件的機器上）：

```bash
pip install sigma-cli
sigma plugin install splunk        # 或 kusto（Sentinel / Defender XDR）、elasticsearch
sigma convert -t splunk -p splunk_windows /srv/adhd/tuned/SubA/windows/
```

關聯規則（密碼噴灑、Kerberoasting、MFA 疲勞）使用 Sigma 2.0 correlation，需要支援 correlation 的 backend。

## 姿態背景

每筆告警都會查詢姿態分析：事件中的 SID、帳號、UPN、主機若是 Tier0、攻擊路徑的起點、或同步成雲端 Tier0，會列在告警中，且告警等級提高一級（例如「非 Tier0 帳號重設 Tier0 密碼」的執行者正好是一條通往 Domain Admins 的路徑起點）。記錄事件的 DC 本身不算涉及對象。

## 涵蓋範圍

| 狀態 | 意義 |
|---|---|
| 已評估 | 有對應的事件，規則已套用 |
| 無事件 | 收集了該來源，但期間內沒有規則需要的事件：常見原因是 DC 沒有啟用對應的稽核原則（見規則目錄的「需要的稽核原則」） |
| 未收集 | 沒有收集該來源，或收集時沒有包含需要的事件 ID |
| 缺環境資料 | 規則需要姿態分析提供的值，但這輪沒有（例如沒有 AD 資料） |

例如 DCSync 規則需要事件 4662，而 4662 只有在啟用「Audit Directory Service Access」並在網域物件上設定 SACL 時才會產生；涵蓋範圍會把這種缺口標成「無事件」並提示原因。

## 重放驗證

- **合成事件**：`detections/tests/*.json`，每個案例列出事件與預期觸發的規則與次數；沒有列出的規則必須保持安靜，所以誤報也會被抓到。`selftest` 與單元測試都會跑。
- **錄製事件**：在 lab AD 以收集器的 DCLogs 模組（或任何匯出成 JSONL 的 Security 事件）錄下攻擊模擬期間的事件，以 `run --events` 重放，確認應該觸發的規則有觸發、正常活動沒有誤報。

新增規則的步驟：在 `detections/sigma/` 新增規則（含 `adhd.title_zh`、`response_zh`、ATT&CK 標籤），在 `detections/tests/` 加上會觸發與不該觸發的案例，跑 `selftest` 與 `lint`，再以 `catalog` 更新規則目錄。

## 限制

- Sigma 支援的是常用子集（見 `adhd/sigma.py` 開頭）；YAML 解析器只支援 Sigma 規則需要的語法，裝有 PyYAML 時改用 PyYAML。
- 收集器的 DCLogs 是固定事件 ID 的取樣（每台 DC 每個 ID 有上限），適合驗證與回溯，不取代 SIEM 的即時收集。
- Defender for Identity / MDE 的告警本身已是偵測；這裡做的是與姿態分析的關聯與優先排序。
