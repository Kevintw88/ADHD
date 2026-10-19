<#
.SYNOPSIS
    Test-ADHDEnabledState.ps1 的模擬測試（pwsh 7，可在 Linux 執行）：以 mock 取代 AD、Graph 與 ADSync。
#>
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$diag = Join-Path $repo 'collectors/powershell/diagnostics/Test-ADHDEnabledState.ps1'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('adhd-diag-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
$failures = 0
function Check([bool] $ok, [string] $msg) { if ($ok) { Write-Output "ok    $msg" } else { Write-Output "FAIL  $msg"; $script:failures++ } }

$D = 'S-1-5-21-1-2-3'
function New-U($rid, $sam, $uac, $changed) {
    [pscustomobject]@{ SID = "$D-$rid"; SamAccountName = $sam; Enabled = (($uac -band 2) -eq 0); userAccountControl = $uac
        whenChanged = [datetime]::SpecifyKind([datetime]$changed, 'Utc'); lastLogonTimestamp = $null; DistinguishedName = "CN=$sam,OU=Staff,DC=sub,DC=local" }
}
$global:Users = @(
    (New-U 1001 'alice' 512 '2026-01-01'), (New-U 1002 'bob' 514 '2026-09-01'),
    (New-U 1003 'carol' 66050 '2026-09-01'), (New-U 1004 'dave' 512 '2026-02-01')
)
function Import-Module { param([Parameter(ValueFromRemainingArguments = $true)] $Rest) }
function Get-Module { param([switch] $ListAvailable, $Name) [pscustomobject]@{ Name = $Name } }
function Get-ADDomain { param($Server) [pscustomobject]@{ PDCEmulator = 'dc1.sub.local' } }
function Get-ADDomainController { param($Filter, $Server) @([pscustomobject]@{ HostName = 'dc1.sub.local' }, [pscustomobject]@{ HostName = 'dc2.sub.local' }) }
function Get-ADUser {
    param($Server, $Filter, $LDAPFilter, $Properties, $ResultPageSize)
    if ($LDAPFilter) {
        if ($Server -eq 'dc2.sub.local') { return @($global:Users | Where-Object { $_.SID -eq "$D-1002" }) }
        return @($global:Users | Where-Object { $_.userAccountControl -band 2 })
    }
    $global:Users
}
function Connect-MgGraph { param($Scopes, $TenantId, $ContextScope, [switch] $NoWelcome) }
function Disconnect-MgGraph { }
function Invoke-MgGraphRequest {
    param($Method, $Uri, $OutputType)
    if ($Uri -like '*organization*') { return [pscustomobject]@{ value = @([pscustomobject]@{ onPremisesLastSyncDateTime = '2026-10-15T07:30:00Z' }) } }
    [pscustomobject]@{ value = @(
            [pscustomobject]@{ id = 'a'; accountEnabled = $true; onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = "$D-1001"; onPremisesLastSyncDateTime = '2026-10-15T07:30:00Z' },
            [pscustomobject]@{ id = 'b'; accountEnabled = $true; onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = "$D-1002"; onPremisesLastSyncDateTime = '2026-10-15T07:30:00Z'; signInActivity = [pscustomobject]@{ lastSignInDateTime = (Get-Date).ToUniversalTime().AddDays(-2).ToString('o') } },
            [pscustomobject]@{ id = 'c'; accountEnabled = $false; onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = "$D-1003"; onPremisesLastSyncDateTime = '2026-10-15T07:30:00Z' }
        ) }
}
# ADSync
function Get-ADSyncScheduler { [pscustomobject]@{ SyncCycleEnabled = $true; StagingModeEnabled = $false } }
function Get-ADSyncRunProfileResult { param($NumberRequested) [pscustomobject]@{ StartDate = (Get-Date); ConnectorName = 'sub.local'; RunProfileName = 'Delta Import'; Result = 'success' } }
function Get-ADSyncRule {
    [pscustomobject]@{ Name = 'In from AD - User AccountEnabled'; Direction = 'Inbound'; Precedence = 104; Disabled = $true
        AttributeFlowMappings = @([pscustomobject]@{ Destination = 'accountEnabled'; Source = @('userAccountControl'); Expression = 'IIF(BitAnd([userAccountControl],2)=0,True,False)' }) }
    [pscustomobject]@{ Name = 'Custom - keep enabled'; Direction = 'Inbound'; Precedence = 50; Disabled = $false
        AttributeFlowMappings = @([pscustomobject]@{ Destination = 'accountEnabled'; Source = @(); Expression = 'True' }) }
    [pscustomobject]@{ Name = 'In from AD - User Common'; Direction = 'Inbound'; Precedence = 105; Disabled = $false
        AttributeFlowMappings = @([pscustomobject]@{ Destination = 'displayName'; Source = @('displayName'); Expression = $null }) }
}
function Get-ADSyncConnector { [pscustomobject]@{ Name = 'sub.local'; Type = 'AD' } }
function Get-ADSyncCSObject { param($ConnectorName, $DistinguishedName)
    [pscustomobject]@{ ConnectedMVObjectId = 'mv1'; Attributes = @([pscustomobject]@{ Name = 'userAccountControl'; Values = @('514') }) } }
function Get-ADSyncMVObject { param($Identifier)
    [pscustomobject]@{ Attributes = @([pscustomobject]@{ Name = 'accountEnabled'; Values = @('True') }) } }

# --- domain mode, all users
$csv1 = Join-Path $tmp 'all.csv'
$out1 = & $diag -OutFile $csv1 6>&1 | Out-String
Check ($out1 -match '三種方式完全一致') 'AD 三方比對一致'
Check ($out1 -match 'dc1\.sub\.local\s+停用 2' -and $out1 -match 'dc2\.sub\.local\s+停用 1') '各 DC 停用數（可看出複寫差異）'
Check ($out1 -match 'AD 停用但 Entra 啟用 1') 'AD / Entra 不一致計數'
Check ($out1 -match '近 30 天有雲端登入：1') '近 30 天雲端登入'
Check ($out1 -match '2\s+2026-09-01') 'whenChanged 分布（同一天批次停用）'
Check ($out1 -match '2\s+OU=Staff,DC=sub,DC=local') '停用帳號所在容器'
$rows = @(Import-Csv $csv1)
Check ($rows.Count -eq 4) 'CSV 4 列'
Check (-not ($rows[0].PSObject.Properties.Name -contains 'SamAccountName')) 'CSV 預設不含帳號名稱'
Check (($rows | Where-Object Sid -eq "$D-1002").EntraAccountEnabled -eq 'True') 'CSV 含 Entra 狀態'

# --- SidFile + IncludeNames + SkipEntra
$sf = Join-Path $tmp 'sids.txt'; Set-Content -Path $sf -Value "$D-1002`n"
$csv2 = Join-Path $tmp 'one.csv'
$out2 = & $diag -SidFile $sf -SkipEntra -IncludeNames -OutFile $csv2 6>&1 | Out-String
$rows2 = @(Import-Csv $csv2)
Check ($rows2.Count -eq 1 -and $rows2[0].SamAccountName -eq 'bob') 'SidFile 篩選與 -IncludeNames'
Check ($out2 -match 'SidFile 中停用 1/1') '各 DC 的 SidFile 統計'

# --- Entra Connect mode
$out3 = & $diag -EntraConnect -SampleDn 'CN=bob,OU=Staff,DC=sub,DC=local' 6>&1 | Out-String
Check ($out3 -match 'Custom - keep enabled' -and $out3 -match 'expr: True') '列出覆寫 accountEnabled 的自訂規則'
Check ($out3 -notmatch 'User Common') '只列出寫入 accountEnabled 的規則'
Check ($out3 -match 'userAccountControl\s+\{?514' -and $out3 -match 'accountEnabled\s+\{?True') '連接器空間與 metaverse 的值'

Remove-Item -Recurse -Force $tmp
if ($failures) { Write-Output "$failures 項失敗"; exit 1 } else { Write-Output '全部通過' }
