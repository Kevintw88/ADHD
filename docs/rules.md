# ADHD 規則目錄

由 `python3 tools/analyze.py --list-rules --markdown` 產生，請勿手動編輯。


## AD

| 規則 | 預設嚴重度 | 標題 | 說明 | 需要的資料集 | ATT&CK |
|---|---|---|---|---|---|
| AD-001 | 中 | krbtgt 密碼過久未重設 | krbtgt 密碼越久未換，遭竊後偽造的 Golden Ticket 可用越久。 | ad_domain | T1558.001 |
| AD-002 | 中 | 一般使用者可自行將電腦加入網域（MachineAccountQuota > 0） | 任何驗證過的使用者可建立電腦帳號，常被用於 RBCD、KrbRelay、noPac 等攻擊鏈。 | ad_domain | T1136.002 |
| AD-003 | 中 | 可被 Kerberoasting 的使用者帳號 | 任何網域使用者都能為有 SPN 的帳號請求服務票證並離線破解其密碼。 | ad_users | T1558.003 |
| AD-004 | 高 | 不需 Kerberos 預先驗證的帳號（AS-REP Roasting） | 攻擊者不需任何憑證即可取得這些帳號可離線破解的加密資料。 | ad_users | T1558.004 |
| AD-005 | 高 | 非網域控制站設定無限制委派 | 任何對這些主機進行驗證的帳號（含 DC 經 Printer Bug 強制驗證）都會留下可重用的 TGT。 | ad_users<br>ad_computers | T1558, T1187 |
| AD-006 | 中 | 限制委派（含協定轉換） | 設有 msDS-AllowedToDelegateTo 的帳號被取得後，可冒用任何使用者存取委派目標。 | ad_users<br>ad_computers | T1558 |
| AD-007 | 中 | 資源型限制委派（RBCD）設定 | 列在 msDS-AllowedToActOnBehalfOfOtherIdentity 的主體可冒用任何使用者存取目標主機。 | ad_computers | T1134 |
| AD-008 | 中 | 啟用中的帳號允許空白密碼（PASSWD_NOTREQD） | 設有此旗標的帳號可被設定為空白密碼，不受密碼原則限制。 | ad_users | T1078.002 |
| AD-009 | 高 | 密碼以可還原加密方式儲存 | 可還原加密的密碼等同明文，取得 NTDS 或 DCSync 即可還原。 | ad_users<br>ad_password_policies | T1003 |
| AD-010 | 中 | Tier0 帳號密碼永不過期 | 密碼永不過期的特權帳號一旦外洩，攻擊者可長期使用。 | ad_users | T1078.002 |
| AD-011 | 中 | Tier0 帳號可被委派 | 未受保護的特權帳號登入有委派設定的主機時，其票證可被冒用。 | ad_users<br>ad_groups | T1558 |
| AD-012 | 中 | 長期未使用的 Tier0 帳號 | 仍啟用但長期未登入的特權帳號容易被忽略，是常見的持久化與橫向移動目標。 | ad_users<br>ad_groups | T1078.002 |
| AD-013 | 中 | 帳號帶有 sIDHistory | sIDHistory 讓帳號在存取時帶有其他 SID 的權限，含特權 SID 時等同隱藏的管理員。 | ad_users | T1134.005 |
| AD-014 | 資訊 | Tier0 成員盤點 | 列出 Tier0 群組的遞移成員，作為後續分析的基準。 | ad_groups<br>ad_users | T1078.002 |
| AD-015 | 中 | LAPS 未部署或覆蓋不完整 | 沒有 LAPS 的主機通常共用本機管理員密碼，一台失守即可橫向移動到其他主機。 | ad_computers<br>ad_domain | T1078.003 |
| AD-016 | 中 | 網域密碼原則偏弱 | 預設密碼原則過弱時，密碼噴灑與暴力破解的成功率明顯提高。 | ad_password_policies | T1110 |
| AD-017 | 高 | 仍在使用已終止支援的作業系統 | 已終止支援的系統不再有安全更新，常是入侵與橫向移動的起點。 | ad_computers | T1210 |
| AD-018 | 高 | 物件描述疑似含有密碼 | 收集器只記錄「疑似含密碼」旗標，不收值；任何網域使用者都能讀取這些欄位。 | ad_users | T1552 |
| AD-019 | 嚴重 | SYSVOL 中的 GPP 密碼（cpassword） | GPP 密碼以公開金鑰加密，任何能讀 SYSVOL 的使用者都能解出明文。 | gpo_gpp_cpassword | T1552.006 |
| AD-020 | 高 | 非 Tier0 主體對 Tier0 物件有控制權限 | 對 Tier0 物件有 GenericAll / WriteDacl / WriteOwner / 改密碼 / 加成員等權限，等同可取得網域控制權。 | ad_acls<br>ad_groups | T1098, T1484.001 |
| AD-021 | 嚴重 | 具 DCSync 權限的非預設主體 | 持有 Get-Changes + Get-Changes-All 的主體可從 DC 複寫出所有帳號（含 krbtgt）的密碼雜湊。 | ad_acls<br>ad_groups | T1003.006 |
| AD-022 | 高 | 網域信任設定風險 | 信任設定不當時，對方網域的入侵可透過 SID history 或 TGT 委派延伸到本網域。 | ad_trusts | T1482, T1134.005 |
| AD-023 | 中 | gMSA 密碼可被非 Tier0 主體讀取 | 能讀取 gMSA 密碼即可以該服務帳號身分登入。由執行服務的主機讀取是正常設計，只回報 Tier0 gMSA 與廣泛群組可讀的情況。 | ad_service_accounts<br>ad_groups | T1555 |
| AD-024 | 中 | Tier0 帳號帶有 Key Credential（可能的 Shadow Credentials） | 攻擊者寫入 msDS-KeyCredentialLink 後可用 PKINIT 以該帳號身分取得票證。注意：低權限收集帳號可能讀不到此屬性。 | ad_users<br>ad_groups | T1556 |
| AD-025 | 低 | 網域功能等級與 AD 資源回收筒 | 較舊的功能等級無法使用 Protected Users 的完整保護、Kerberos armoring 等功能。 | ad_domain<br>ad_forest | — |
| AD-026 | 高 | dSHeuristics 放寬安全設定 | dSHeuristics 可開放匿名 LDAP 存取，或讓特定特權群組不受 AdminSDHolder 保護。 | ad_domain | T1087.002 |
| AD-027 | 中 | Pre-Windows 2000 相容存取群組包含匿名或 Everyone | 此群組有網域物件的大範圍讀取權，包含匿名時等同未驗證即可列舉網域。 | ad_groups | T1087.002 |
| AD-028 | 低 | 長期未使用但仍啟用的帳號 | 閒置帳號沒有人注意其異常登入，常被用於持久化。 | ad_users<br>ad_computers | T1078.002 |
| AD-029 | 低 | adminCount=1 但已不在特權群組 | 曾經是特權成員的帳號保留 adminCount 與鎖定的 ACL，常是遺留的特權帳號或權限漂移的跡象。 | ad_users<br>ad_groups | — |
| AD-030 | 中 | 內建 Guest 帳號已啟用 | 啟用的 Guest 帳號允許不具名存取。 | ad_users | T1078.001 |

## ADCS

| 規則 | 預設嚴重度 | 標題 | 說明 | 需要的資料集 | ATT&CK |
|---|---|---|---|---|---|
| ADCS-001 | 高 | ESC1：可自行指定憑證主體的驗證用範本 | 申請者可在要求中填入任意 UPN / SAN，申請到網域管理員的驗證憑證。 | adcs_templates<br>adcs_cas<br>ad_groups | T1649 |
| ADCS-002 | 高 | ESC2：任何用途 / 無 EKU 的範本 | Any Purpose 或沒有 EKU 的憑證可用於用戶端驗證，也可作為下級 CA 簽發其他憑證。 | adcs_templates<br>adcs_cas<br>ad_groups | T1649 |
| ADCS-003 | 高 | ESC3：註冊代理（Certificate Request Agent）範本 | 取得註冊代理憑證後，可代替任何使用者申請其他範本的憑證。 | adcs_templates<br>adcs_cas<br>ad_groups | T1649 |
| ADCS-004 | 高 | ESC4：非 Tier0 主體可修改憑證範本 | 能修改範本即可把它改成 ESC1 再申請憑證。 | adcs_templates<br>ad_groups | T1649 |
| ADCS-005 | 高 | ESC5：非 Tier0 主體可控制 PKI 物件 | 能修改 NTAuthCertificates、CA 物件或範本容器，即可讓自製的 CA 或範本被網域信任。 | adcs_containers<br>adcs_cas<br>ad_groups | T1649 |
| ADCS-006 | 中 | ESC9：不含安全性延伸的驗證範本 | 憑證不含 SID 延伸時，搭配可改寫 UPN 的帳號即可取得他人身分的憑證（DC 未完全強制強式對應時）。 | adcs_templates<br>adcs_cas<br>ad_groups | T1649 |
| ADCS-007 | 資訊 | ADCS 伺服器端設定未評估（ESC6 / ESC7 / ESC8 / ESC11） | 這些弱點設定在 CA 主機的登錄機碼與服務上，本版收集器未收集。 | adcs_cas | T1649 |

## Entra

| 規則 | 預設嚴重度 | 標題 | 說明 | 需要的資料集 | ATT&CK |
|---|---|---|---|---|---|
| EN-001 | 中 | Global Administrator 人數 | Global Administrator 過多會擴大攻擊面；少於 2 個則沒有緊急存取備援。 | entra_role_assignments<br>entra_users | T1078.004 |
| EN-002 | 高 | 特權角色持有者未註冊 MFA | 未註冊 MFA 的特權帳號只靠密碼保護。 | entra_role_assignments<br>entra_user_registration | T1078.004, T1110 |
| EN-003 | 高 | 來賓帳號持有特權角色 | 來賓帳號的驗證與生命週期由對方租用戶控制。 | entra_role_assignments<br>entra_users | T1078.004 |
| EN-004 | 高 | 服務主體持有特權目錄角色 | 服務主體不受 MFA / CA 保護，取得其憑證即可以特權角色操作租用戶。 | entra_role_assignments<br>entra_service_principals | T1098.001, T1078.004 |
| EN-005 | 中 | 特權角色常駐指派（未透過 PIM 啟用） | 常駐的特權角色在帳號遭入侵時立即可用，也無法留下啟用紀錄。 | entra_role_assignments | T1078.004 |
| EN-006 | 高 | 未強制 MFA | 沒有 Security Defaults 也沒有要求 MFA 的 CA 原則時，帳號只靠密碼保護。 | entra_ca_policies 或 entra_security_defaults | T1078.004, T1110.003 |
| EN-007 | 高 | 未封鎖舊式驗證 | 舊式驗證協定不支援 MFA，是密碼噴灑最常用的入口。 | entra_ca_policies 或 entra_security_defaults | T1110.003 |
| EN-008 | 中 | 條件式存取原則的排除對象 | 被排除的帳號不受 MFA / 封鎖原則保護，常成為攻擊者的目標。 | entra_ca_policies | T1078.004 |
| EN-009 | 資訊 | 未啟用或僅報告模式的條件式存取原則 | 報告模式與停用的原則不會產生任何保護。 | entra_ca_policies | — |
| EN-010 | 中 | 一般使用者可註冊應用程式 | 任何使用者建立的 App 都可要求權限並成為網路釣魚同意攻擊或持久化的載體。 | entra_authorization_policy | T1098.001 |
| EN-011 | 高 | 使用者可自行同意應用程式權限 | 使用者可同意任意 App 的委派權限時，同意網路釣魚（illicit consent grant）即可取得信箱與檔案存取。 | entra_authorization_policy | T1528 |
| EN-012 | 中 | 來賓存取設定寬鬆 | 來賓權限與成員相同時可列舉整個目錄；任何人都能邀請時無法控管外部帳號。 | entra_authorization_policy | T1078.004 |
| EN-013 | 高 | 服務主體持有高風險應用程式權限 | 應用程式權限不需使用者登入、不受 CA / MFA 限制；部分權限可直接提升為 Global Administrator。 | entra_app_role_assignments<br>entra_service_principals | T1098.001, T1528 |
| EN-014 | 中 | 應用程式憑證衛生 | 長效 secret 外洩風險高；服務主體層級的密碼不顯示在 App 註冊頁面，常被用作後門。 | entra_applications<br>entra_service_principals | T1098.001 |
| EN-015 | 高 | 管理員同意的高風險委派權限 | 代表整個組織同意的委派權限，讓 App 能以任何登入使用者的身分存取資料（仍受該使用者本身權限限制）。 | entra_oauth2_grants | T1528 |
| EN-016 | 高 | Identity Protection 風險使用者 | Identity Protection 判定帳號可能已遭入侵。 | entra_risky_users | T1078.004 |
| EN-017 | 低 | 長期未登入的來賓帳號 | 閒置的來賓帳號保留對租用戶資源的存取，且沒有人監控。 | entra_users | T1078.004 |
| EN-018 | 高 | 特權物件的擁有者不是特權帳號 | 群組擁有者可加自己為成員；App / 服務主體擁有者可新增憑證並以其身分操作。 | entra_role_assignments<br>entra_group_memberships | T1098, T1098.001 |
| EN-019 | 高 | Entra Connect 伺服器的本機管理員不是 Tier0 | Entra Connect 伺服器保存具 DCSync 權限的 connector 帳號憑證，本機管理員即可取得。 | entraconnect_server<br>ad_groups | T1003.006, T1078.002 |
| EN-020 | 中 | Seamless SSO 金鑰（AZUREADSSOACC）久未輪替 | 取得 AZUREADSSOACC 的金鑰即可為任何同步使用者偽造登入 Entra ID 的 Kerberos 票證（Silver Ticket）。 | ad_computers | T1558.002 |
| EN-021 | 中 | 長期未登入的特權帳號（Entra） | 閒置的特權帳號容易被忽略，且常沒有現行的 MFA 註冊。 | entra_role_assignments<br>entra_users | T1078.004 |
| EN-022 | 資訊 | 同盟驗證網域 | 同盟網域的登入由外部 IdP 簽發權杖，取得簽章金鑰即可偽造任何使用者（Golden SAML）。 | entra_domains | T1606.002 |

## Hybrid

| 規則 | 預設嚴重度 | 標題 | 說明 | 需要的資料集 | ATT&CK |
|---|---|---|---|---|---|
| HY-001 | 高 | 雲端特權角色由地端同步帳號持有 | 同步帳號的密碼與狀態由 AD 決定：能重設該 AD 帳號密碼的人（含 AD 的服務台委派）即可取得雲端特權。 | entra_role_assignments<br>entra_users | T1078.002, T1078.004 |
| HY-002 | 中 | AD Tier0 帳號同步到 Entra ID | AD 特權帳號同步後，其密碼雜湊也同步到雲端，雲端端的釣魚或權杖竊取會直接威脅 AD Tier0。 | ad_users<br>ad_groups<br>entra_users | T1078.002 |
| HY-003 | 資訊 | Entra Connect 組態摘要 | 彙整 Entra Connect 的伺服器、版本、同步模式與 connector 帳號，供後續分析與報告使用。 | entraconnect_server | T1003.006 |
| HY-004 | 嚴重 | Entra Connect 的 AD DS connector 帳號權限過高或被當成一般帳號使用 | connector 帳號的密碼保存在 Entra Connect 伺服器上，該伺服器的本機管理員可以取出。帳號若是 Tier0 群組成員，取得伺服器即取得網域。 | entraconnect_connectors<br>ad_users<br>ad_groups<br>ad_acls | T1003.006, T1555, T1078.002 |
| HY-005 | 高 | AD 已停用但 Entra 仍啟用的同步帳號 | Entra Connect 預設會把 AD 的停用狀態同步到 Entra。兩邊不一致代表「在 AD 停用帳號」（一般的離職流程）沒有關閉雲端存取。 | ad_users<br>entra_users | T1078.004 |

## Path

| 規則 | 預設嚴重度 | 標題 | 說明 | 需要的資料集 | ATT&CK |
|---|---|---|---|---|---|
| PATH-001 | 高 | 非 Tier0 主體有通往 Tier0 的攻擊路徑 | 單看一條權限常常只是「中」，串起來才看得出某個普通帳號只要幾步就能拿到網域或租用戶的最高權限。每個起點只列最便宜的一條路徑（成員關係不計步數）；起點是實際持有第一個可濫用權限的主體，透過群組成員關係共用同一路徑的帳號計入 exposedAccounts。 | ad_users<br>ad_groups<br>ad_acls | T1078, T1098, T1484, T1003.006 |
| PATH-002 | 資訊 | 攻擊路徑的關鍵步驟（優先切斷） | 最多帳號的最短路徑都經過的步驟：處理一條就能切斷最多路徑。 | ad_users<br>ad_groups<br>ad_acls | T1078 |
