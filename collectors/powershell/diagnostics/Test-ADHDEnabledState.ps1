#Requires -Version 5.1
<#
.SYNOPSIS
    唯讀診斷：確認 AD 與 Entra ID 的帳號啟用狀態是否一致（驗證 ADHD 的 HY-005 與「AD 啟用帳號偏少」）。

.DESCRIPTION
    預設模式（網域成員主機，一般網域使用者即可）：
      1. 以三種彼此獨立的方式判斷每個使用者是否停用：
           a. AD 模組的 Enabled 屬性（收集器使用的方式）
           b. userAccountControl 原始值的 ACCOUNTDISABLE 位元（0x2，用戶端計算）
           c. LDAP 伺服器端位元比對篩選 (userAccountControl:1.2.840.113556.1.4.803:=2)
      2. 每台 DC（含站台）各自回報的停用帳號數，以及 DC 之間的複寫狀態與失敗紀錄
      3. 停用帳號的 whenChanged 日期與 OU 分布（判斷是否為一次性批次停用）
      4. Entra ID（可用 -SkipEntra 略過）：accountEnabled、onPremisesSyncEnabled、
         onPremisesLastSyncDateTime、最後登入，並與 AD 比對
      5. 問題帳號的 userAccountControl 複寫中繼資料：在哪台 DC、何時被修改；抽樣帳號在每台 DC 上的值與版本號

    -EntraConnect 模式（在 Entra Connect 伺服器上，以系統管理員執行）：
      同步排程、最近的執行結果、Entra Connect 從哪台 DC 讀取 AD（站台、偏好 DC、匯入時實際連線的 DC）、
      所有會寫入 accountEnabled 的同步規則（是否被停用或被較優先的自訂規則覆寫），
      以及指定帳號（-SampleDn）在連接器空間與 metaverse 中的值。

    只讀取，不修改任何設定。輸出的 CSV 預設只含 SID 與狀態，不含姓名與帳號（加 -IncludeNames 才會列出）。

.PARAMETER SidFile
    只檢查清單中的 SID（每行一個）。lab 端以 tools/diag_enabled.py --sids-out 產生。

.EXAMPLE
    # 網域成員主機：AD 三方比對 + 各 DC + Entra（*> 會把所有輸出存到檔案，方便回傳）
    .\Test-ADHDEnabledState.ps1 -TenantId cortinaaccess.onmicrosoft.com *> .\enabled-check.log

.EXAMPLE
    # 只檢查 lab 提供的 SID 清單
    .\Test-ADHDEnabledState.ps1 -SidFile .\mismatch-sids.txt -TenantId cortinaaccess.onmicrosoft.com

.EXAMPLE
    # Entra Connect 伺服器（Windows PowerShell 5.1，系統管理員）
    .\Test-ADHDEnabledState.ps1 -EntraConnect -SampleDn 'CN=某使用者,OU=Users,DC=Cortina-Access,DC=com'
#>
[CmdletBinding()]
param(
    [switch] $EntraConnect,
    [string] $SampleDn,
    [string] $SidFile,
    [string] $Server,
    [string] $TenantId,
    [switch] $SkipEntra,
    [switch] $IncludeNames,
    [string] $OutFile = (".\ADHD-EnabledState-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmm'))
)

$ErrorActionPreference = 'Stop'
$script:DisabledFilter = '(userAccountControl:1.2.840.113556.1.4.803:=2)'

function Write-Section {
    param([string] $Title)
    Write-Host ''
    Write-Host "== $Title ==" -ForegroundColor Cyan
}

function ConvertTo-UtcText {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-dd HH:mm') }
    $d = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) {
        return $d.ToString('yyyy-MM-dd HH:mm')
    }
    return $null
}

function Get-ParentContainer {
    param([string] $Dn)
    $parts = ([regex]'(?<!\\),').Split([string]$Dn, 2)   # instance overload: second argument is the count
    if ($parts.Count -eq 2) { return $parts[1] }
    return '?'
}

function Get-DsaServerName {
    # 'CN=NTDS Settings,CN=DC01,CN=Servers,CN=Taipei,CN=Sites,...' -> 'DC01 (Taipei)'
    param($Dsa)
    $m = [regex]::Match([string]$Dsa, 'CN=NTDS Settings(?:\\0ADEL:[^,]*)?,CN=([^,]+),CN=Servers,CN=([^,]+)', 'IgnoreCase')
    if ($m.Success) { return '{0} ({1})' -f $m.Groups[1].Value, $m.Groups[2].Value }
    if ("$Dsa") { return [string]$Dsa }
    return '（未知）'
}

# =============================================================================================
function Invoke-ReplicationHealth {
    param([string] $Target)
    Write-Section '網域內 DC 之間的複寫（Get-ADReplicationPartnerMetadata，預設命名內容）'
    try {
        $meta = @(Get-ADReplicationPartnerMetadata -Target $Target -Scope Domain -Partition Default -ErrorAction Stop)
        $meta | Sort-Object Server, Partner | Select-Object @{ n = 'DC'; e = { $_.Server } },
            @{ n = '複寫來源'; e = { Get-DsaServerName $_.Partner } },
            @{ n = '最後成功(UTC)'; e = { ConvertTo-UtcText $_.LastReplicationSuccess } },
            @{ n = '連續失敗'; e = { $_.ConsecutiveReplicationFailures } },
            @{ n = '最後結果'; e = { $_.LastReplicationResult } } |
            Format-Table -AutoSize | Out-String -Width 220 | Write-Host
        $limit = (Get-Date).AddHours(-24)
        $bad = @($meta | Where-Object { $_.ConsecutiveReplicationFailures -gt 0 -or
                ($_.LastReplicationSuccess -and ([datetime]$_.LastReplicationSuccess) -lt $limit) })
        if ($bad.Count -gt 0) {
            Write-Host ("有 {0} 條複寫連線失敗或超過 24 小時沒有成功：不同 DC 上的帳號狀態可能不一致。" -f $bad.Count) -ForegroundColor Yellow
        }
        else { Write-Host '所有複寫連線在 24 小時內成功、沒有連續失敗。' -ForegroundColor Green }
    }
    catch {
        Write-Host "無法讀取複寫中繼資料：$($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host '改用：repadmin /replsummary 以及 repadmin /showrepl * /csv'
    }

    Write-Section '複寫失敗紀錄（Get-ADReplicationFailure）'
    try {
        $fail = @(Get-ADReplicationFailure -Target $Target -Scope Domain -ErrorAction Stop | Where-Object { $_.FailureCount -gt 0 })
        if ($fail.Count -eq 0) { Write-Host '沒有複寫失敗紀錄。' -ForegroundColor Green }
        else {
            $fail | Select-Object Server, @{ n = 'Partner'; e = { Get-DsaServerName $_.Partner } }, FailureCount,
                @{ n = 'FirstFailure(UTC)'; e = { ConvertTo-UtcText $_.FirstFailureTime } }, LastError |
                Format-Table -AutoSize | Out-String -Width 220 | Write-Host
        }
    }
    catch { Write-Host "無法讀取：$($_.Exception.Message)" -ForegroundColor Yellow }
}

function Invoke-AttributeMetadataCheck {
    # Targets: objects with Sid and Dn.  Who originated the current userAccountControl value, and does every DC agree?
    param([object[]] $Targets, [object[]] $Dcs, [string] $Dc0, [string] $Label, [int] $SampleSize = 3)
    if (-not $Targets -or $Targets.Count -eq 0) { return }
    $Targets = @($Targets | Select-Object -First 300)
    $metaErr = $null

    Write-Section ("{0}：userAccountControl 最後是在哪台 DC、何時修改（{1} 個帳號，查詢 {2}）" -f $Label, $Targets.Count, $Dc0)
    $origin = @(foreach ($t in $Targets) {
            try {
                $m = @(Get-ADReplicationAttributeMetadata -Object $t.Dn -Server $Dc0 -Properties userAccountControl -ErrorAction Stop |
                        Where-Object { $_.AttributeName -eq 'userAccountControl' })[0]
                if ($m) {
                    [pscustomobject]@{ Origin = Get-DsaServerName $m.LastOriginatingChangeDirectoryServerIdentity
                        Day = $(if ($m.LastOriginatingChangeTime) { (ConvertTo-UtcText $m.LastOriginatingChangeTime).Substring(0, 10) } else { '（無）' }) }
                }
            }
            catch { $metaErr = $_.Exception.Message }
        })
    if ($metaErr) { Write-Host "部分帳號讀取失敗（最後一個錯誤：$metaErr）" -ForegroundColor Yellow }
    if ($origin.Count -eq 0) { Write-Host '無法讀取複寫中繼資料。' -ForegroundColor Yellow; return }
    $origin | Group-Object Origin | Sort-Object Count -Descending | Select-Object Count, @{ n = '修改所在 DC (站台)'; e = { $_.Name } } |
        Format-Table -AutoSize | Out-String -Width 220 | Write-Host
    $origin | Group-Object Day | Sort-Object Count -Descending | Select-Object -First 5 Count, @{ n = '修改日 (UTC)'; e = { $_.Name } } |
        Format-Table -AutoSize | Out-String -Width 220 | Write-Host

    $sample = @($Targets | Select-Object -First $SampleSize)
    Write-Section ("抽樣 {0} 個帳號在每台 DC 上的值（版本號與停用狀態應全部相同）" -f $sample.Count)
    $diff = 0
    $i = 0
    foreach ($t in $sample) {
        $i++
        $perDc = @(foreach ($dc in $Dcs) {
                $h = [string]$dc.HostName
                try {
                    $u = Get-ADUser -Identity $t.Dn -Server $h -Properties userAccountControl -ErrorAction Stop
                    $m = @(Get-ADReplicationAttributeMetadata -Object $t.Dn -Server $h -Properties userAccountControl -ErrorAction Stop |
                            Where-Object { $_.AttributeName -eq 'userAccountControl' })[0]
                    [pscustomobject]@{ '帳號' = "#$i"; DC = $h; Site = $dc.Site; UAC = [int]$u.userAccountControl
                        '停用' = (([int]$u.userAccountControl -band 2) -ne 0); Version = $(if ($m) { $m.Version } else { $null })
                        'LastChange(UTC)' = $(if ($m) { ConvertTo-UtcText $m.LastOriginatingChangeTime } else { $null }) }
                }
                catch { [pscustomobject]@{ '帳號' = "#$i"; DC = $h; Site = $dc.Site; UAC = $null; '停用' = $null; Version = $null; 'LastChange(UTC)' = "無法查詢：$($_.Exception.Message)" } }
            })
        $perDc | Format-Table -AutoSize | Out-String -Width 220 | Write-Host
        $ok = @($perDc | Where-Object { $null -ne $_.UAC })
        if (@($ok | Select-Object -ExpandProperty Version -Unique).Count -gt 1 -or @($ok | Select-Object -ExpandProperty '停用' -Unique).Count -gt 1) { $diff++ }
    }
    if ($diff -gt 0) {
        Write-Host ("{0}/{1} 個抽樣帳號在不同 DC 上的值不同：停用狀態沒有複寫到所有 DC。" -f $diff, $sample.Count) -ForegroundColor Yellow
        Write-Host '  判讀：若 Entra Connect 讀的 DC（用 -EntraConnect 模式確認）是「未停用」的那台，Entra 就會維持啟用。'
    }
    else {
        Write-Host '抽樣帳號在每台 DC 上的值相同：複寫不是原因，請看 -EntraConnect 模式的同步規則與執行結果。' -ForegroundColor Green
    }
}

# =============================================================================================
function Invoke-EntraConnectCheck {
    Import-Module ADSync -ErrorAction Stop

    Write-Section '同步排程'
    Get-ADSyncScheduler |
        Select-Object SyncCycleEnabled, StagingModeEnabled, MaintenanceEnabled, CurrentlyEffectiveSyncCycleInterval,
                      NextSyncCycleStartTimeInUTC, NextSyncCyclePolicyType |
        Format-List | Out-String -Width 220 | Write-Host

    $runs = @(Get-ADSyncRunProfileResult -NumberRequested 20)
    Write-Section '最近 20 次執行結果（Result 不是 success 的要特別注意）'
    $runs | Select-Object StartDate, ConnectorName, RunProfileName, Result |
        Format-Table -AutoSize | Out-String -Width 220 | Write-Host

    Write-Section 'Entra Connect 從哪台 DC 讀取 AD'
    try {
        $site = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name
        $loc = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().FindDomainController().Name
        Write-Host "本機所在站台：$site；DC 定位器目前選到：$loc"
    }
    catch { Write-Host "無法取得本機站台：$($_.Exception.Message)" -ForegroundColor Yellow }
    $adConnectors = @(Get-ADSyncConnector | Where-Object { [string]$_.Type -eq 'AD' })
    foreach ($c in $adConnectors) {
        foreach ($part in @($c.Partitions)) {
            $pref = @($part.PSObject.Properties | Where-Object { $_.Name -match 'Preferred|DomainController' -and "$($_.Value)" } |
                    ForEach-Object { '{0}={1}' -f $_.Name, (@($_.Value) -join ',') })
            Write-Host ("  連接器 {0}／分割 {1}：{2}" -f $c.Name, $part.Name,
                $(if ($pref) { $pref -join '；' } else { '未設定偏好 DC（依站台自動選擇）' }))
        }
    }
    $adNames = @($adConnectors | ForEach-Object { [string]$_.Name })
    $used = @(foreach ($r in $runs) {
            if ($adNames -notcontains [string]$r.ConnectorName) { continue }
            foreach ($s in @($r.RunStepResults)) {
                $m = [regex]::Match([string]$s.ConnectorConnectionInformationXml, '<server>([^<]+)</server>', 'IgnoreCase')
                if ($m.Success) { [pscustomobject]@{ StartDate = $r.StartDate; RunProfile = $r.RunProfileName; DC = $m.Groups[1].Value } }
            }
        })
    if ($used.Count -gt 0) {
        Write-Host '  最近幾次匯入實際連線的 DC：'
        $used | Format-Table -AutoSize | Out-String -Width 220 | Write-Host
    }
    else {
        Write-Host '  執行紀錄中沒有連線資訊；請在 Synchronization Service Manager → Operations → 選一次 AD 的 Import → Connection Status 查看。'
    }
    Write-Host '判讀：把這台 DC 與網域模式「抽樣帳號在每台 DC 上的值」對照；若它是停用沒有複寫到的那台，就是 Entra 維持啟用的原因。'

    Write-Section '會寫入 accountEnabled 的同步規則'
    $rules = @(Get-ADSyncRule | Where-Object {
            @($_.AttributeFlowMappings | ForEach-Object { $_.Destination }) -contains 'accountEnabled' })
    if ($rules.Count -eq 0) {
        Write-Host '找不到任何寫入 accountEnabled 的規則：AD 的停用狀態不會同步到 Entra。' -ForegroundColor Yellow
    }
    $rules | Sort-Object Direction, Precedence | Select-Object Name, Direction, Precedence, Disabled,
        @{ n = 'Flow'; e = { (@($_.AttributeFlowMappings | Where-Object { $_.Destination -eq 'accountEnabled' } | ForEach-Object {
                        if ($_.Expression) { "expr: $($_.Expression)" } else { "src: $(@($_.Source) -join ',')" } })) -join ' | ' } } |
        Format-List | Out-String -Width 220 | Write-Host
    Write-Host '判讀：預設的「In from AD - User AccountEnabled」以 userAccountControl 計算 accountEnabled。'
    Write-Host '      若它 Disabled=True，或有 Precedence 數字更小（較優先）的 Inbound 自訂規則也寫入 accountEnabled，'
    Write-Host '      AD 的停用就可能不會帶到 Entra。'

    if ($SampleDn) {
        Write-Section "帳號在同步引擎中的值：$SampleDn"
        $ad = @(Get-ADSyncConnector | Where-Object { [string]$_.Type -eq 'AD' }) | Select-Object -First 1
        if (-not $ad) { Write-Host '找不到 AD 連接器'; return }
        try {
            $cs = Get-ADSyncCSObject -ConnectorName $ad.Name -DistinguishedName $SampleDn
            $cs.Attributes | Where-Object { $_.Name -in @('userAccountControl', 'objectSid') } |
                Select-Object Name, Values | Format-Table -AutoSize | Out-String -Width 220 | Write-Host
            if ($cs.ConnectedMVObjectId -and (Get-Command Get-ADSyncMVObject -ErrorAction SilentlyContinue)) {
                $mv = Get-ADSyncMVObject -Identifier $cs.ConnectedMVObjectId
                $mv.Attributes | Where-Object { $_.Name -in @('accountEnabled', 'cloudFiltered', 'sourceAnchor') } |
                    Select-Object Name, Values | Format-Table -AutoSize | Out-String -Width 220 | Write-Host
            }
        }
        catch { Write-Host "讀取失敗：$($_.Exception.Message)" -ForegroundColor Yellow }
        Write-Host '判讀：連接器空間的 userAccountControl 若含 0x2（例如 514、66050）而 metaverse 的 accountEnabled 仍為 True，'
        Write-Host '      代表同步規則沒有把停用狀態帶過去；若 cloudFiltered=True，代表物件已被篩選出同步範圍。'
    }
}

# =============================================================================================
function Get-EntraUsers {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw '找不到 Microsoft.Graph.Authentication 模組（Install-Module Microsoft.Graph.Authentication -Scope CurrentUser）'
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $mg = @{ Scopes = @('User.Read.All', 'AuditLog.Read.All', 'Organization.Read.All'); ErrorAction = 'Stop' }
    $cmd = Get-Command Connect-MgGraph
    if ($cmd.Parameters.ContainsKey('ContextScope')) { $mg.ContextScope = 'Process' }
    if ($cmd.Parameters.ContainsKey('NoWelcome')) { $mg.NoWelcome = $true }
    if ($TenantId) { $mg.TenantId = $TenantId }
    Connect-MgGraph @mg | Out-Null
    try {
        $org = Invoke-MgGraphRequest -Method GET -OutputType PSObject `
            -Uri 'v1.0/organization?$select=onPremisesSyncEnabled,onPremisesLastSyncDateTime'
        $orgRow = @($org.value)[0]
        $select = 'id,accountEnabled,onPremisesSyncEnabled,onPremisesSecurityIdentifier,onPremisesLastSyncDateTime'
        $uri = "v1.0/users?`$top=999&`$select=$select,signInActivity"
        try { [void](Invoke-MgGraphRequest -Method GET -OutputType PSObject -Uri $uri) }
        catch {
            Write-Host '無法讀取 signInActivity（授權或權限不足），改為不含最後登入時間。' -ForegroundColor Yellow
            $uri = "v1.0/users?`$top=999&`$select=$select"
        }
        $users = New-Object System.Collections.Generic.List[object]
        while ($uri) {
            $resp = Invoke-MgGraphRequest -Method GET -OutputType PSObject -Uri $uri
            foreach ($u in @($resp.value)) { $users.Add($u) }
            $uri = $resp.'@odata.nextLink'
        }
        return [pscustomobject]@{ Organization = $orgRow; Users = $users }
    }
    finally {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}

function Invoke-DomainCheck {
    Import-Module ActiveDirectory -ErrorAction Stop
    $p = @{}
    if ($Server) { $p.Server = $Server }
    $dom = Get-ADDomain @p
    $dc0 = $(if ($Server) { $Server } else { [string]$dom.PDCEmulator })

    $only = $null
    if ($SidFile) {
        $only = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($line in [System.IO.File]::ReadAllLines((Resolve-Path $SidFile).Path)) {
            if ($line.Trim()) { [void]$only.Add($line.Trim()) }
        }
        Write-Host "只檢查 SidFile 中的 $($only.Count) 個 SID"
    }

    Write-Section "AD 三種判斷方式比對（查詢 DC：$dc0）"
    $users = @(Get-ADUser -Server $dc0 -Filter * -ResultPageSize 500 `
            -Properties userAccountControl, whenChanged, lastLogonTimestamp, pwdLastSet)
    $ldapDisabled = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($u in @(Get-ADUser -Server $dc0 -LDAPFilter $script:DisabledFilter -ResultPageSize 500)) {
        [void]$ldapDisabled.Add([string]$u.SID)
    }

    $entra = $null
    if (-not $SkipEntra) {
        Write-Section 'Entra ID'
        try { $entra = Get-EntraUsers }
        catch { Write-Host "Entra 讀取失敗，只做 AD 部分：$($_.Exception.Message)" -ForegroundColor Yellow }
    }
    $entraBySid = @{}
    if ($entra) {
        foreach ($e in $entra.Users) {
            if ($e.onPremisesSecurityIdentifier) { $entraBySid[[string]$e.onPremisesSecurityIdentifier] = $e }
        }
        Write-Host ("Entra 使用者 {0} 個；租用戶最後目錄同步：{1} UTC" -f $entra.Users.Count,
            (ConvertTo-UtcText $entra.Organization.onPremisesLastSyncDateTime))
    }

    $dnBySid = @{}
    $rows = foreach ($u in $users) {
        $sid = [string]$u.SID
        if ($only -and -not $only.Contains($sid)) { continue }
        $dnBySid[$sid] = [string]$u.DistinguishedName
        $uac = [int]$u.userAccountControl
        $row = [ordered]@{ Sid = $sid }
        if ($IncludeNames) { $row.SamAccountName = $u.SamAccountName }
        $row.AdModuleEnabled = [bool]$u.Enabled
        $row.UacValue = $uac
        $row.UacDisabledBit = (($uac -band 2) -ne 0)
        $row.LdapFilterDisabled = $ldapDisabled.Contains($sid)
        $row.WhenChangedUtc = ConvertTo-UtcText $u.whenChanged
        $ll = [long]$u.lastLogonTimestamp
        $row.LastLogonTimestampUtc = $(if ($ll -gt 0) { [datetime]::FromFileTimeUtc($ll).ToString('yyyy-MM-dd HH:mm') } else { $null })
        $row.ParentContainer = Get-ParentContainer $u.DistinguishedName
        $e = $entraBySid[$sid]
        $row.EntraFound = [bool]$e
        $row.EntraAccountEnabled = $(if ($e) { [bool]$e.accountEnabled } else { $null })
        $row.EntraSynced = $(if ($e) { [bool]$e.onPremisesSyncEnabled } else { $null })
        $row.EntraLastSyncUtc = $(if ($e) { ConvertTo-UtcText $e.onPremisesLastSyncDateTime } else { $null })
        $sia = $(if ($e) { $e.signInActivity } else { $null })
        $row.EntraLastSignInUtc = $(if ($sia) { ConvertTo-UtcText $(if ($sia.lastSignInDateTime) { $sia.lastSignInDateTime } else { $sia.lastNonInteractiveSignInDateTime }) } else { $null })
        [pscustomobject]$row
    }
    $rows = @($rows)

    $total = $rows.Count
    $modEn = @($rows | Where-Object { $_.AdModuleEnabled }).Count
    $bitDis = @($rows | Where-Object { $_.UacDisabledBit }).Count
    $ldapDis = @($rows | Where-Object { $_.LdapFilterDisabled }).Count
    $disagree = @($rows | Where-Object { ($_.AdModuleEnabled -eq $_.UacDisabledBit) -or ($_.UacDisabledBit -ne $_.LdapFilterDisabled) })
    Write-Section 'AD 結果'
    Write-Host ("檢查帳號 {0}：AD 模組 Enabled=True {1} / False {2}；UAC 位元停用 {3}；LDAP 篩選停用 {4}" -f $total, $modEn, ($total - $modEn), $bitDis, $ldapDis)
    if ($disagree.Count -eq 0) {
        Write-Host '三種方式完全一致：收集器讀到的停用狀態與 AD 實際值相同。' -ForegroundColor Green
    }
    else {
        Write-Host ("有 {0} 個帳號三種方式不一致（請把 CSV 中這些列回報）" -f $disagree.Count) -ForegroundColor Yellow
    }

    $dcs = @(Get-ADDomainController -Filter * -Server $dc0)
    Write-Section ("各 DC 的停用帳號數（{0} 台；複寫正常時應全部相同）" -f $dcs.Count)
    $counts = @()
    foreach ($dc in $dcs) {
        $tag = $(if ([string]$dc.HostName -eq [string]$dom.PDCEmulator) { ' [PDC，收集器查詢的 DC]' } elseif ($dc.IsReadOnly) { ' [RODC]' } else { '' })
        try {
            $set = @(Get-ADUser -Server ([string]$dc.HostName) -LDAPFilter $script:DisabledFilter -ResultPageSize 500)
            $counts += $set.Count
            $inList = $(if ($only) { @($set | Where-Object { $only.Contains([string]$_.SID) }).Count } else { $null })
            # one Write-Host per line: -NoNewline pieces become separate records when redirected with *>
            $line = "  {0,-30} {1,-18} 停用 {2}" -f $dc.HostName, $dc.Site, $set.Count
            if ($null -ne $inList) { $line += "（SidFile 中停用 {0}/{1}）" -f $inList, $only.Count }
            Write-Host ($line + $tag)
        }
        catch { Write-Host ("  {0,-30} {1,-18} 無法查詢：{2}{3}" -f $dc.HostName, $dc.Site, $_.Exception.Message, $tag) -ForegroundColor Yellow }
    }
    if (@($counts | Select-Object -Unique).Count -gt 1) {
        Write-Host '各 DC 的數字不同：有 DC 之間的複寫沒有同步（看下方「複寫」段落）。' -ForegroundColor Yellow
    }

    Invoke-ReplicationHealth -Target ([string]$dom.DNSRoot)

    $disabled = @($rows | Where-Object { $_.UacDisabledBit })
    if ($disabled.Count -gt 0) {
        Write-Section '停用帳號的最後修改日（whenChanged）'
        $disabled | Group-Object { if ($_.WhenChangedUtc) { $_.WhenChangedUtc.Substring(0, 10) } else { '（無）' } } |
            Sort-Object Count -Descending | Select-Object -First 8 Count, Name | Format-Table -AutoSize | Out-String -Width 220 | Write-Host
        Write-Section '停用帳號所在容器'
        $disabled | Group-Object ParentContainer | Sort-Object Count -Descending | Select-Object -First 8 Count, Name |
            Format-Table -AutoSize | Out-String -Width 220 | Write-Host
    }

    if ($entra) {
        $synced = @($rows | Where-Object { $_.EntraFound -and $_.EntraSynced })
        $mism = @($synced | Where-Object { $_.UacDisabledBit -and $_.EntraAccountEnabled })
        Write-Section 'AD 與 Entra 比對（同步帳號）'
        Write-Host ("同步帳號 {0}：都啟用 {1}、都停用 {2}、AD 停用但 Entra 啟用 {3}、AD 啟用但 Entra 停用 {4}" -f $synced.Count,
            @($synced | Where-Object { -not $_.UacDisabledBit -and $_.EntraAccountEnabled }).Count,
            @($synced | Where-Object { $_.UacDisabledBit -and -not $_.EntraAccountEnabled }).Count,
            $mism.Count,
            @($synced | Where-Object { -not $_.UacDisabledBit -and -not $_.EntraAccountEnabled }).Count)
        if ($mism.Count -gt 0) {
            $after = @($mism | Where-Object { $_.EntraLastSyncUtc -and $_.WhenChangedUtc -and ($_.EntraLastSyncUtc -gt $_.WhenChangedUtc) }).Count
            $recent = @($mism | Where-Object { $_.EntraLastSignInUtc -and ([datetime]$_.EntraLastSignInUtc -gt (Get-Date).ToUniversalTime().AddDays(-30)) }).Count
            Write-Host ("  其中近 30 天有雲端登入：{0}；Entra 最後同步晚於 AD 最後修改：{1}/{2}" -f $recent, $after, $mism.Count)
            Write-Host '  判讀：同步晚於修改卻仍為啟用 → 同步規則 / 屬性篩選沒有帶停用狀態（用 -EntraConnect 模式確認規則）；'
            Write-Host '        AD 修改後就沒再同步 → 同步停止、匯出錯誤或物件已不在同步範圍。'
        }
    }

    # replication metadata for the population in question: the AD-disabled / Entra-enabled accounts when Entra
    # was read, otherwise the disabled accounts being checked
    if ($entra -and $mism -and $mism.Count -gt 0) { $focus = $mism; $label = 'AD 停用、Entra 啟用的帳號' }
    else { $focus = $disabled; $label = '停用帳號' }
    Invoke-AttributeMetadataCheck -Targets @($focus | ForEach-Object { [pscustomobject]@{ Sid = $_.Sid; Dn = $dnBySid[$_.Sid] } }) `
        -Dcs $dcs -Dc0 $dc0 -Label $label

    $rows | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    Write-Host ''
    Write-Host "明細已寫入 $OutFile$(if (-not $IncludeNames) { '（只含 SID 與狀態，可回傳 lab）' } else { '（含帳號名稱，請留在子公司）' })"
}

# =============================================================================================
if ($MyInvocation.InvocationName -ne '.') {
    if ($EntraConnect) { Invoke-EntraConnectCheck } else { Invoke-DomainCheck }
}
