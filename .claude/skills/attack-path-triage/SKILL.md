---
name: attack-path-triage
description: 解讀通往 Tier 0 的攻擊路徑並排定修補順序。當使用者問「誰能到達 Domain Admins / Entra Connect / 全域管理員」、「先修哪一個」、「這條路徑怎麼被濫用」時使用。
---

# 攻擊路徑分流手冊

## 步驟

1. 呼叫 `bloodhound.path_summary`，取得來源數、可達數與建議修補順序。
2. 修補順序是工具實際移除每條邊後重算的結果，直接採用，不要自行重排。
3. 對前 3 個修補步驟，逐一說明：
   - 這條邊代表什麼權限（見下表）
   - 攻擊者如何濫用
   - 修補方式與修補前要確認的相依性
4. 使用者指定帳號或主機時，用 `path_from_principal` 或 `who_can_reach` 查證，不要憑代表路徑推論。

## 邊的意義

| 邊 | 意義 | 常見修補 |
| --- | --- | --- |
| MemberOf | 群組成員，繼承群組權限 | 檢討成員資格 |
| GenericAll / GenericWrite / WriteDacl | 對物件有完整或可寫入的 ACL | 移除 ACE，改用委派精確權限 |
| AdminTo | 主機本機管理員 | 移除群組、部署 LAPS |
| HasSession | 特權帳號在該主機有登入工作階段，憑證可被竊取 | 特權帳號只登入 Tier 0 主機、啟用 Protected Users |
| Enroll + ADCSESC1 | 可註冊允許自填主體、可用於驗證的憑證範本，偽造任何人 | 移除自填主體或加主管核准、縮小註冊權 |
| DCSync | 可複寫網域密碼雜湊 | 只保留 DC 與必要帳號 |
| SyncedToEntraUser | 地端帳號同步到雲端，取得地端即取得雲端 | 雲端特權帳號改用純雲端帳號 |
| HybridControl | 同步層主機（Entra Connect / AD FS / PTA）可控制雲端身分 | 列為 Tier 0、限制管理員 |
| AZAddSecret / AZOwns | 可替應用程式新增密鑰或擁有應用程式 | 移除擁有者、限制 Application Administrator |
| AZDangerousAppPermission | 應用程式權限可提升為全域管理員 | 改為最小權限 |

## 回覆格式

- 結論：多少比例的帳號可到達 Tier 0、第一步修補可切斷多少
- 修補順序表：步驟、邊、切斷數、修補方式、需確認事項
- 需人工確認：工具無法判斷的業務相依性
