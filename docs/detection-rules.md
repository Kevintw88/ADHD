# ADHD 偵測規則目錄

由 `python3 tools/detect.py catalog` 產生，請勿手動編輯。

| 規則 | 等級 | 來源 | 事件 / 條件 | 需要的稽核原則 | 環境資料 | ATT&CK |
|---|---|---|---|---|---|---|
| 指派了 Entra Tier0 角色<br>`61d5bc8a-3cd2-535e-a9cf-1c4c1c8f1b3e` | 高 | azure/auditlogs | — | — | — | T1098.003 |
| 應用程式取得同意授權<br>`a391529c-5011-528e-bd8f-91ae72f7c24b` | 中 | azure/auditlogs | — | — | — | T1528 |
| 應用程式或服務主體被新增憑證<br>`c470bc0f-dd47-57cd-9d49-7bfdf4774de7` | 中 | azure/auditlogs | — | — | — | T1098.001 |
| 條件式存取原則被新增、修改或刪除<br>`ba8713d1-b05d-585a-b0b4-8d7343c74243` | 中 | azure/auditlogs | — | — | — | T1556.009 |
| 網域的同盟或驗證設定被變更<br>`fd69607a-3e74-55e7-a26b-67fcb85d5e25` | 高 | azure/auditlogs | — | — | — | T1484.002 |
| 以舊式驗證通訊協定成功登入<br>`0f3746b1-3bc5-52ff-8836-9b6fa0944154` | 中 | azure/signinlogs | — | — | — | T1078.004 |
| 高風險登入仍然成功<br>`27d48a4d-867f-5d47-bcf2-198a7f94469e` | 高 | azure/signinlogs | — | — | — | T1078.004 |
| MFA 驗證被拒或未完成<br>`5a5b6cca-fae9-5bdc-a7b1-a8319056c6b6`（只供關聯使用） | 低 | azure/signinlogs | — | — | — | T1621 |
| Entra 登入密碼錯誤<br>`2265e4b4-24cb-5abf-8a11-0704a500933a`（只供關聯使用） | 低 | azure/signinlogs | — | — | — | T1110 |
| Entra Tier0 管理員從未受管理的裝置登入<br>`ad66efe2-abe4-5bad-9a09-7fbad2dbc691` | 中 | azure/signinlogs | — | — | entra_tier0_users | T1078.004 |
| Defender for Identity 告警涉及 Tier0 帳號<br>`e0d4c161-cf5d-5942-bae3-be0b6be6368e` | 高 | m365defender/alerts | — | — | tier0_accounts |  |
| Defender 告警涉及 Tier0 主機（DC、Entra Connect、CA）<br>`9b1c6015-99de-5c19-9350-670ea5cc7416` | 高 | m365defender/alerts | — | — | tier0_hosts |  |
| Defender for Identity 高嚴重度告警<br>`d15705a7-9b52-551a-9ab9-31c94ae1cb63` | 中 | m365defender/alerts | — | — | — |  |
| 未經預先驗證就簽發的 TGT（AS-REP Roasting）<br>`a06c6239-939a-5a8f-bdf0-03ef2117704b` | 中 | windows/security | 4768 | Audit Kerberos Authentication Service | — | T1558.004 |
| DC 的安全性事件記錄被清除<br>`ccd7d8a7-abb9-593b-90f5-3c82f35c1399` | 高 | windows/security | 1102 | （一律記錄） | — | T1070.001 |
| 稽核原則被變更<br>`89c785a7-e0c5-524c-a5a2-de055f665685` | 中 | windows/security | 4719 | Audit Audit Policy Change | — | T1562.002 |
| DSRM 密碼被變更<br>`8ed4f93e-364e-571c-81fa-c0d671bd8d36` | 高 | windows/security | 4794 | Audit User Account Management | — | T1098 |
| 非網域控制站帳號執行目錄複寫（DCSync）<br>`414fdf36-f2c5-501b-8ccf-ed878f5554e1` | 高 | windows/security | 4662 | Audit Directory Service Access + domain object SACL | dcsync_expected | T1003.006 |
| AdminSDHolder 被修改<br>`8bb21765-52e2-585e-85d9-a0560ec8846f` | 高 | windows/security | 5136 | Audit Directory Service Changes + SACL | — | T1484.001 |
| 帳號被寫入 Key Credential（Shadow Credentials）<br>`60f032c0-b8d7-5994-9a2e-55d3d539ec20` | 高 | windows/security | 5136 | Audit Directory Service Changes + SACL | keycred_writers | T1556 |
| 設定了資源型限制委派（RBCD）<br>`e409c6f9-a675-540e-8291-4cb52982e1e5` | 高 | windows/security | 5136 | Audit Directory Service Changes + SACL | — | T1134 |
| 使用者帳號被新增 SPN（定向 Kerberoasting）<br>`ddeeeab0-d7a8-5f9e-b3d9-970cb6216698` | 中 | windows/security | 5136 | Audit Directory Service Changes + SACL | — | T1558.003 |
| GPO 設定或 GPO 連結變更<br>`f1efc93b-dcca-595d-b5e1-89638b2385ea` | 中 | windows/security | 5136 | Audit Directory Service Changes + SACL | — | T1484.001 |
| 以 RC4 加密簽發的 Kerberos 服務票證<br>`08034dfb-cd73-593c-bc12-190df3a32a58`（只供關聯使用） | 低 | windows/security | 4769 | Audit Kerberos Service Ticket Operations | — | T1558.003 |
| 有人以 RC4 申請 Tier0 帳號 SPN 的服務票證<br>`a9cb4811-0404-5e1c-ac94-9708e9c414b1` | 高 | windows/security | 4769 | Audit Kerberos Service Ticket Operations | tier0_accounts | T1558.003 |
| 驗證失敗（密碼錯誤）<br>`bc261a05-b9e7-5ce1-af93-7f1e58aafc8c`（只供關聯使用） | 低 | windows/security | 4625, 4771 | Audit Kerberos Authentication Service<br>Audit Logon | — | T1110 |
| Tier0 群組新增成員<br>`34789217-4a77-59ce-b3ce-71a4889afce4` | 高 | windows/security | 4728, 4732, 4756 | Audit Security Group Management | tier0_groups | T1098 |
| 非 Tier0 帳號重設 Tier0 帳號的密碼<br>`adc00d88-ce77-562b-b5fb-0d733f6300f5` | 高 | windows/security | 4724 | Audit User Account Management | tier0_accounts | T1098 |
| MFA 疲勞攻擊：同一使用者短時間多次 MFA 失敗<br>`e043ecdb-447e-52f7-b511-7d1fa9650fc6` | 高 | 關聯 | event_count：userPrincipalName 在 10m 內 gte 5 | 同基礎規則 | — | T1621 |
| Entra 密碼噴灑：同一 IP 對大量使用者嘗試密碼<br>`eb5bc318-d089-51e7-9768-dd16b59e753a` | 高 | 關聯 | value_count：ipAddress 在 10m 內 gte 10（userPrincipalName） | 同基礎規則 | — | T1110.003 |
| Kerberoasting：同一帳號短時間申請多個 RC4 服務票證<br>`bb4f5491-8ab7-532a-97e7-722f6ee34418` | 高 | 關聯 | value_count：TargetUserName, IpAddress 在 10m 內 gte 5（ServiceName） | 同基礎規則 | — | T1558.003 |
| 密碼噴灑：同一來源對大量帳號嘗試密碼<br>`4a269c2a-7c2e-5491-9131-610a38983066` | 高 | 關聯 | value_count：IpAddress 在 10m 內 gte 10（TargetUserName） | 同基礎規則 | — | T1110.003 |
| 暴力破解：單一帳號短時間大量密碼錯誤<br>`9d1d4619-5341-5739-bece-e6732eb4cb01` | 中 | 關聯 | event_count：TargetUserName 在 10m 內 gte 20 | 同基礎規則 | — | T1110.001 |
