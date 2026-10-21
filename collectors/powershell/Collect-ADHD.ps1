#Requires -Version 5.1
<#
.SYNOPSIS
    ADHD 離線資料收集器：以「唯讀」方式收集 AD / Entra ID 混合環境的安全組態，
    打包成可帶回 lab 離線分析的 bundle（JSONL + manifest.json）。

.DESCRIPTION
    本腳本只做 LDAP / Microsoft Graph / Event Log 的讀取，不會修改任何目標環境設定。

    模組（-Include）:
      AD            Forest/Domain、密碼原則、Trust、DC、OU/gPLink、Users、Computers、gMSA、Groups
      ADACL         高價值物件的 DACL（Domain root、AdminSDHolder、OU、adminCount=1、GPO、DC、同步帳號）
      GPO           GPO 清單、GPO XML 報表、SYSVOL GPP cpassword「存在與否」掃描（不收值）
      ADCS          CA、憑證範本（含 ESC 相關旗標）與 PKI 容器 ACL
      EntraConnect  Entra Connect 組態（需在 Entra Connect 伺服器上、以系統管理員執行）
      Entra         Entra ID 物件、角色/PIM、條件式存取、驗證方法、App/SP 與權限
      EntraLogs     Entra 登入 / 稽核 / 風險偵測紀錄（需 Entra ID P1/P2）
      SecurityAlerts Defender for Identity / Endpoint 告警（Graph security/alerts_v2，SecurityAlert.Read.All）
      DCLogs        DC Security 事件取樣（需 Event Log Readers 與遠端事件記錄存取）

    絕對不收集：密碼雜湊、NTDS.dit、LAPS 密碼值、BitLocker 復原金鑰、gMSA 密碼、
    App secret / 私鑰、GPP cpassword 值。程式以「明確列出屬性」+「禁止欄位過濾」雙重把關。

    預設啟用假名化：使用者姓名、帳號、UPN、Email 以 HMAC-SHA256 轉為 u-xxxxxxxxxxxx，
    SID / objectId / 群組名稱 / 主機名稱保留，讓攻擊路徑分析仍可運作。
    金鑰與對照表寫在 bundle 資料夾「之外」，請留在子公司，不要帶回 lab。

.PARAMETER Include
    要執行的模組。預設 AD, ADACL, GPO, ADCS, Entra。

.PARAMETER OutputRoot
    輸出根目錄，bundle 會建立在其下的 ADHD-Collect-<Label>-<UTC 時間> 資料夾。

.PARAMETER Label
    bundle 名稱標籤，例如子公司代號。預設為電腦名稱。

.PARAMETER Server
    指定查詢的 DC。未指定時固定使用 PDC Emulator，確保整份快照來自同一台 DC。

.PARAMETER Credential
    AD 查詢用的替代認證（GroupPolicy 模組與 SYSVOL 掃描不支援，會使用目前登入身分）。

.PARAMETER TenantId
    Entra 租用戶 ID 或預設網域（例如 contoso.onmicrosoft.com）。

.PARAMETER GraphClientId
    使用子公司自建的 App registration 進行 delegated 登入（未指定則使用 Microsoft Graph Command Line Tools）。

.PARAMETER UseDeviceCode
    使用裝置代碼登入 Graph（適用於無瀏覽器的伺服器）。

.PARAMETER FullAcl
    額外收集所有 user / group / computer 的明確 ACE（資料量大）。

.PARAMETER AllGroupMembers
    收集所有 Entra 群組的成員；預設只收可指派角色、具角色指派或被條件式存取引用的群組。

.PARAMETER LogDays
    EntraLogs / DCLogs / SecurityAlerts 往回收集的天數（1-30）。

.PARAMETER MaxLogRecords
    每個 Entra 紀錄資料集的筆數上限。

.PARAMETER DomainControllers
    DCLogs 要讀取的 DC 清單；未指定則讀取網域內所有 DC。

.PARAMETER EventIds
    DCLogs 收集的 Security 事件 ID。

.PARAMETER MaxEventsPerId
    DCLogs 每台 DC、每個事件 ID 的筆數上限。

.PARAMETER PseudonymKeyFile
    假名化金鑰檔。預設為 <OutputRoot>\ADHD-pseudonym.key；檔案存在就沿用（跨次收集假名一致），不存在就產生。

.PARAMETER NoPseudonymize
    關閉假名化（僅限已取得資料擁有者同意，或測試環境）。

.PARAMETER NoMappingFile
    不輸出假名 → 原值對照表。

.PARAMETER SkipGpoXml
    不輸出 GPO XML 報表。

.PARAMETER NoZip
    不壓縮 bundle。

.EXAMPLE
    # 網域成員主機（RSAT-AD、GPMC、Microsoft.Graph.Authentication），收集 AD + Entra
    .\Collect-ADHD.ps1 -Label SubA -TenantId sub-a.onmicrosoft.com

.EXAMPLE
    # 在 Entra Connect 伺服器上（Windows PowerShell 5.1，以系統管理員執行）
    .\Collect-ADHD.ps1 -Label SubA-AADC -Include EntraConnect

.EXAMPLE
    # 指定 DC，並加收 Entra 紀錄與 DC 安全事件
    .\Collect-ADHD.ps1 -Label SubA -Server dc01.sub-a.local -Include AD,ADACL,GPO,ADCS,Entra,EntraLogs,DCLogs -LogDays 7

.NOTES
    Project : ADHD (AD + Entra ID Hybrid Defense)
    Version : 0.1.0
    Output  : schema adhd.collect/1，詳見 collectors/powershell/README.md
#>
[CmdletBinding()]
param(
    [ValidateSet('AD', 'ADACL', 'GPO', 'ADCS', 'EntraConnect', 'Entra', 'EntraLogs', 'DCLogs', 'SecurityAlerts')]
    [string[]] $Include = @('AD', 'ADACL', 'GPO', 'ADCS', 'Entra'),

    [string] $OutputRoot = '.',

    [string] $Label = $env:COMPUTERNAME,

    [string] $Server,

    [System.Management.Automation.PSCredential] $Credential,

    [string] $TenantId,

    [string] $GraphClientId,

    [switch] $UseDeviceCode,

    [switch] $FullAcl,

    [switch] $AllGroupMembers,

    [ValidateRange(1, 30)]
    [int] $LogDays = 7,

    [ValidateRange(1, 5000000)]
    [int] $MaxLogRecords = 50000,

    [string[]] $DomainControllers,

    [int[]] $EventIds = @(
        4624, 4625, 4648, 4672,                   # 登入 / 特權登入
        4768, 4769, 4771, 4776,                   # Kerberos / NTLM 驗證
        4720, 4722, 4724, 4725, 4726, 4738, 4740, 4767,  # 帳號管理
        4728, 4729, 4732, 4733, 4756, 4757,       # 群組成員異動
        4662, 5136, 5137, 5141,                   # 目錄服務存取 / 變更
        4719, 1102, 4794                          # 稽核原則變更 / 清除紀錄 / DSRM 密碼
    ),

    [ValidateRange(1, 1000000)]
    [int] $MaxEventsPerId = 2000,

    [string] $PseudonymKeyFile,

    [switch] $NoPseudonymize,

    [switch] $NoMappingFile,

    [switch] $SkipGpoXml,

    [switch] $NoZip
)

# ---------------------------------------------------------------------------
# 常數
# ---------------------------------------------------------------------------
$script:CollectorVersion = '0.1.3'
$script:SchemaVersion    = 'adhd.collect/1'
$script:Utf8NoBom        = New-Object System.Text.UTF8Encoding -ArgumentList $false

# Microsoft 第一方應用程式所屬租用戶（per-SP 呼叫時排除）
$script:MicrosoftTenantIds = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')

# 任何層級出現這些欄位名稱都會被丟棄（第二道防線；第一道是明確列出要讀的屬性）
$script:ForbiddenKeys = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
@(
    'ms-Mcs-AdmPwd', 'msLAPS-Password', 'msLAPS-EncryptedPassword', 'msLAPS-EncryptedPasswordHistory',
    'msLAPS-EncryptedDSRMPassword', 'msLAPS-EncryptedDSRMPasswordHistory',
    'msFVE-RecoveryPassword', 'msFVE-KeyPackage', 'msTPM-OwnerInformation',
    'unicodePwd', 'dBCSPwd', 'ntPwdHistory', 'lmPwdHistory', 'supplementalCredentials',
    'userPassword', 'unixUserPassword', 'msDS-ManagedPassword',
    'cpassword', 'password', 'secretText', 'clientSecret', 'privateKey', 'hint', 'key'
) | ForEach-Object { [void]$script:ForbiddenKeys.Add($_) }

$script:EmailRegex      = [regex]'(?<![\w.%+\-#/])[\w.%+\-#]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}'
$script:PseudoEmailRegex = [regex]'^u-[0-9a-f]{12}@'
$script:DnFirstRdnRegex = [regex]'^CN=((?:\\.|[^,\\])+)(,.*)?$'
$script:TextDnRegex     = [regex]'CN=((?:\\.|[^,\\=<>"])+)(?=,)'
$script:XmlAccountRegex = [regex]'>([^<>\\\r\n]{1,64})\\([^<>\\\r\n]{1,256})<'
$script:XmlTextRegex    = [regex]'>([^<>\r\n]{2,256})<'
$script:JsonEscapeRegex = [regex]'[\u0000-\u001f"\\\u007f\u2028\u2029]'
$script:SecretHintRegex = [regex]'(?i)(passw|pwd|pass\s*[:=]|pw\s*[:=]|密碼|secret)'
$script:InfraAccountRegex = [regex]'(?i)^(MSOL_|Sync_|AAD_|AZUREADSSOACC|provAgentgMSA|ADToAADSyncServiceAccount|krbtgt)'

$script:UacFlagTable = [ordered]@{
    SCRIPT                         = 0x1
    ACCOUNTDISABLE                 = 0x2
    HOMEDIR_REQUIRED               = 0x8
    PASSWD_NOTREQD                 = 0x20
    ENCRYPTED_TEXT_PWD_ALLOWED     = 0x80
    NORMAL_ACCOUNT                 = 0x200
    INTERDOMAIN_TRUST_ACCOUNT      = 0x800
    WORKSTATION_TRUST_ACCOUNT      = 0x1000
    SERVER_TRUST_ACCOUNT           = 0x2000
    DONT_EXPIRE_PASSWORD           = 0x10000
    SMARTCARD_REQUIRED             = 0x40000
    TRUSTED_FOR_DELEGATION         = 0x80000
    NOT_DELEGATED                  = 0x100000
    USE_DES_KEY_ONLY               = 0x200000
    DONT_REQ_PREAUTH               = 0x400000
    PASSWORD_EXPIRED               = 0x800000
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
    PARTIAL_SECRETS_ACCOUNT        = 0x4000000
}

# ---------------------------------------------------------------------------
# Regex evaluators（假名化）
# ---------------------------------------------------------------------------
$script:EmailEvaluator = [System.Text.RegularExpressions.MatchEvaluator] {
    param($m)
    if ($script:PseudoEmailRegex.IsMatch($m.Value)) { return $m.Value }
    Get-ADHDPseudonym $m.Value
}
$script:XmlAccountEvaluator = [System.Text.RegularExpressions.MatchEvaluator] {
    param($m)
    $h = $null
    if ($script:Ctx.PiiMap.TryGetValue($m.Groups[2].Value, [ref]$h)) { '>' + $m.Groups[1].Value + '\' + $h + '<' } else { $m.Value }
}
$script:XmlTextEvaluator = [System.Text.RegularExpressions.MatchEvaluator] {
    param($m)
    $h = $null
    if ($script:Ctx.PiiMap.TryGetValue($m.Groups[1].Value, [ref]$h)) { '>' + $h + '<' } else { $m.Value }
}
$script:TextDnEvaluator = [System.Text.RegularExpressions.MatchEvaluator] {
    param($m)
    $h = $null
    $cn = $m.Groups[1].Value -replace '\\(.)', '$1'
    if ($script:Ctx.PiiMap.TryGetValue($cn, [ref]$h)) { 'CN=' + $h } else { $m.Value }
}
$script:JsonEscapeEvaluator = [System.Text.RegularExpressions.MatchEvaluator] {
    param($m)
    $c = [int][char]$m.Value
    switch ($c) {
        34      { '\"' }
        92      { '\\' }
        10      { '\n' }
        13      { '\r' }
        9       { '\t' }
        8       { '\b' }
        12      { '\f' }
        default { '\u{0:x4}' -f $c }
    }
}

# ===========================================================================
# 基礎工具
# ===========================================================================
function Resolve-ADHDPath {
    param([string] $Path)
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function Write-ADHDLog {
    param(
        [string] $Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')] [string] $Level = 'INFO'
    )
    $safe = Protect-ADHDText $Message
    $line = '{0} [{1}] {2}' -f [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'), $Level, $safe
    if ($script:Ctx -and $script:Ctx.LogPath) {
        [System.IO.File]::AppendAllText($script:Ctx.LogPath, $line + [Environment]::NewLine, $script:Utf8NoBom)
    }
    switch ($Level) {
        'WARN'  { Write-Warning $Message; if ($script:Ctx) { $script:Ctx.Warnings.Add($safe) } }
        'ERROR' { Write-Host $line -ForegroundColor Red; if ($script:Ctx) { $script:Ctx.Warnings.Add($safe) } }
        default { Write-Host $line }
    }
}

function Test-ADHDModule {
    param([string] $Name)
    if ($script:ADHDTestHooks) { return ($script:ADHDTestHooks.AvailableModules -contains $Name) }
    return [bool](Get-Module -ListAvailable -Name $Name)
}

function Import-ADHDModule {
    param([string] $Name)
    if ($script:ADHDTestHooks) { $script:Ctx.ModuleVersions[$Name] = 'test'; return }
    Import-Module -Name $Name -ErrorAction Stop -Verbose:$false -WarningAction SilentlyContinue
    $m = Get-Module -Name $Name | Select-Object -First 1
    if ($m) { $script:Ctx.ModuleVersions[$Name] = $m.Version.ToString() }
}

function ConvertTo-ADHDArray {
    param($Value)
    if ($null -eq $Value) { return , @() }
    return , @($Value)
}

function ConvertTo-ADHDStringArray {
    # 注意：`$null | ForEach-Object {}` 會執行一次，因此改用 foreach 敘述
    param($Value)
    $list = New-Object System.Collections.Generic.List[string]
    if ($null -ne $Value) {
        foreach ($v in $Value) { if ($null -ne $v) { $list.Add([string]$v) } }
    }
    return , $list.ToArray()
}

function Get-ADHDAces {
    param($SdInfo)
    if ($null -eq $SdInfo -or $null -eq $SdInfo.aces) { return , @() }
    return , $SdInfo.aces.ToArray()
}

function Get-ADHDCount {
    param($Value)
    if ($null -eq $Value) { return 0 }
    return @($Value).Count
}

function ConvertFrom-ADHDFileTime {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }
    $n = [long]0
    if (-not [long]::TryParse([string]$Value, [ref]$n)) { return $null }
    if ($n -le 0 -or $n -ge 2650467743999999999) { return $null }
    return [DateTime]::FromFileTimeUtc($n)
}

function ConvertTo-ADHDGuidString {
    param($Bytes)
    if ($Bytes -is [byte[]] -and $Bytes.Length -eq 16) { return ([guid]::new($Bytes)).ToString() }
    return $null
}

function Get-ADHDRid {
    param([string] $Sid)
    if ($Sid -match '^S-1-5-21-[\d-]+-(\d+)$') { return [int]$Matches[1] }
    return -1
}

function Test-ADHDBuiltinSid {
    param([string] $Sid)
    if (-not $Sid) { return $false }
    if ($Sid.StartsWith('S-1-5-32-')) { return $true }
    $rid = Get-ADHDRid $Sid
    return ($rid -ge 0 -and $rid -lt 1000)
}

function Test-ADHDSecretHint {
    param([string] $Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    return $script:SecretHintRegex.IsMatch($Text)
}

function Test-ADHDInfraAccount {
    param([string] $Name)
    if ([string]::IsNullOrEmpty($Name)) { return $false }
    return $script:InfraAccountRegex.IsMatch($Name)
}

function Get-ADHDUacFlags {
    param([int] $Uac)
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($k in $script:UacFlagTable.Keys) {
        if (($Uac -band $script:UacFlagTable[$k]) -ne 0) { $list.Add($k) }
    }
    return , $list.ToArray()
}

function Get-ADHDDnCn {
    param([string] $Dn)
    if ([string]::IsNullOrEmpty($Dn)) { return $null }
    $m = $script:DnFirstRdnRegex.Match($Dn)
    if (-not $m.Success) { return $null }
    return ($m.Groups[1].Value -replace '\\(.)', '$1')
}

function ConvertFrom-ADHDGpLink {
    param([string] $GpLink)
    $list = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrEmpty($GpLink)) { return , $list.ToArray() }
    $order = 0
    foreach ($m in [regex]::Matches($GpLink, '\[LDAP://[Cc][Nn]=(\{[0-9A-Fa-f\-]{36}\}),[^;\]]*;(\d+)\]')) {
        $opt = [int]$m.Groups[2].Value
        $order++
        $list.Add([ordered]@{
            gpoGuid  = $m.Groups[1].Value.Trim('{}').ToLowerInvariant()
            enabled  = (($opt -band 1) -eq 0)
            enforced = (($opt -band 2) -ne 0)
            order    = $order
        })
    }
    return , $list.ToArray()
}

# ===========================================================================
# 假名化
# ===========================================================================
function Initialize-ADHDPseudonymizer {
    param([string] $KeyFile, [switch] $Disabled)
    if ($Disabled) {
        $script:Ctx.Pseudo = $false
        Write-ADHDLog '假名化已關閉（-NoPseudonymize）。請確認已取得資料擁有者同意。' 'WARN'
        return
    }
    if (-not $KeyFile) { $KeyFile = Join-Path $script:Ctx.OutputRoot 'ADHD-pseudonym.key' }
    $KeyFile = Resolve-ADHDPath $KeyFile
    if (Test-Path -LiteralPath $KeyFile) {
        $key = [Convert]::FromBase64String(([System.IO.File]::ReadAllText($KeyFile)).Trim())
        if ($key.Length -lt 32) { throw "假名化金鑰長度不足 32 bytes：$KeyFile" }
        Write-ADHDLog "沿用既有假名化金鑰：$KeyFile"
    }
    else {
        $key = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($key)
        $rng.Dispose()
        [System.IO.File]::WriteAllText($KeyFile, [Convert]::ToBase64String($key), $script:Utf8NoBom)
        Write-ADHDLog "已產生新的假名化金鑰：$KeyFile（請保存在子公司，不要隨 bundle 帶走；下次收集沿用可維持假名一致）" 'WARN'
    }
    $script:Ctx.Hmac = New-Object System.Security.Cryptography.HMACSHA256 -ArgumentList (, $key)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $script:Ctx.KeyId = ([BitConverter]::ToString($sha.ComputeHash($key), 0, 4)).Replace('-', '').ToLowerInvariant()
    $sha.Dispose()
    $script:Ctx.KeyFile = $KeyFile
    $script:Ctx.Pseudo = $true
}

function Get-ADHDPseudonym {
    param([string] $Value)
    $norm = $Value.Trim().ToLowerInvariant()
    $hash = $script:Ctx.Hmac.ComputeHash($script:Utf8NoBom.GetBytes($norm))
    $hex = ([BitConverter]::ToString($hash, 0, 6)).Replace('-', '').ToLowerInvariant()
    $at = $norm.LastIndexOf('@')
    if ($at -gt 0 -and $at -lt $norm.Length - 1 -and $norm.IndexOf(' ') -lt 0) {
        return 'u-' + $hex + $norm.Substring($at)
    }
    return 'u-' + $hex
}

function Register-ADHDPii {
    param([object[]] $Values)
    if (-not $script:Ctx.Pseudo) { return }
    foreach ($v in $Values) {
        if ($null -eq $v) { continue }
        if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
            foreach ($x in $v) { Register-ADHDPii -Values @($x) }
            continue
        }
        $s = ([string]$v).Trim()
        if ($s.Length -lt 2) { continue }
        if ($script:Ctx.PiiMap.ContainsKey($s)) { continue }
        $p = Get-ADHDPseudonym $s
        $script:Ctx.PiiMap[$s] = $p
        if (-not $script:Ctx.PiiReverse.ContainsKey($p)) { $script:Ctx.PiiReverse[$p] = $s }
    }
}

function Protect-ADHDString {
    param([string] $Text, [bool] $Preserve = $false)
    if ([string]::IsNullOrEmpty($Text) -or -not $script:Ctx -or -not $script:Ctx.Pseudo) { return $Text }
    if (-not $Preserve) {
        $hit = $null
        if ($script:Ctx.PiiMap.TryGetValue($Text, [ref]$hit)) { return $hit }
        if ($Text.Length -gt 3 -and $Text.StartsWith('CN=', [System.StringComparison]::OrdinalIgnoreCase)) {
            $m = $script:DnFirstRdnRegex.Match($Text)
            if ($m.Success) {
                $cn = $m.Groups[1].Value -replace '\\(.)', '$1'
                if ($script:Ctx.PiiMap.TryGetValue($cn, [ref]$hit)) { return 'CN=' + $hit + $m.Groups[2].Value }
            }
            return $Text
        }
        $bs = $Text.IndexOf('\')
        if ($bs -gt 0 -and $bs -lt $Text.Length - 1 -and $Text.Length -lt 300 -and $Text.IndexOf('\', $bs + 1) -lt 0) {
            if ($script:Ctx.PiiMap.TryGetValue($Text.Substring($bs + 1), [ref]$hit)) { return $Text.Substring(0, $bs + 1) + $hit }
        }
    }
    if ($Text.IndexOf('@') -ge 0) { return $script:EmailRegex.Replace($Text, $script:EmailEvaluator) }
    return $Text
}

function Protect-ADHDText {
    param([string] $Text)
    if ([string]::IsNullOrEmpty($Text) -or -not $script:Ctx -or -not $script:Ctx.Pseudo) { return $Text }
    $t = $script:XmlAccountRegex.Replace($Text, $script:XmlAccountEvaluator)
    $t = $script:XmlTextRegex.Replace($t, $script:XmlTextEvaluator)
    $t = $script:TextDnRegex.Replace($t, $script:TextDnEvaluator)
    if ($t.IndexOf('@') -ge 0) { $t = $script:EmailRegex.Replace($t, $script:EmailEvaluator) }
    return $t
}

# ===========================================================================
# JSON 序列化（自行實作：相容 Windows PowerShell 5.1，並在序列化時套用假名化與禁止欄位過濾）
# ===========================================================================
function Add-ADHDJsonString {
    param([System.Text.StringBuilder] $Sb, [string] $Text)
    [void]$Sb.Append('"')
    if ($script:JsonEscapeRegex.IsMatch($Text)) { [void]$Sb.Append($script:JsonEscapeRegex.Replace($Text, $script:JsonEscapeEvaluator)) }
    else { [void]$Sb.Append($Text) }
    [void]$Sb.Append('"')
}

function Add-ADHDJson {
    param(
        [System.Text.StringBuilder] $Sb,
        $Value,
        [int] $Depth = 0,
        [System.Collections.Generic.HashSet[string]] $Preserve,
        [bool] $PreserveThis = $false
    )
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    if ($null -eq $Value) { [void]$Sb.Append('null'); return }
    if ($Value -is [string]) { Add-ADHDJsonString $Sb (Protect-ADHDString $Value $PreserveThis); return }
    if ($Value -is [char]) { Add-ADHDJsonString $Sb ([string]$Value); return }
    if ($Value -is [bool]) { [void]$Sb.Append($(if ([bool]$Value) { 'true' } else { 'false' })); return }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte] -or $Value -is [sbyte] -or
        $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [decimal]) {
        [void]$Sb.Append([string]::Format($inv, '{0}', $Value)); return
    }
    if ($Value -is [double] -or $Value -is [single]) {
        $d = [double]$Value
        if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) { [void]$Sb.Append('null') }
        else { [void]$Sb.Append($d.ToString('R', $inv)) }
        return
    }
    if ($Value -is [datetime]) {
        $dt = [datetime]$Value
        if ($dt -eq [datetime]::MinValue -or $dt -eq [datetime]::MaxValue) { [void]$Sb.Append('null'); return }
        Add-ADHDJsonString $Sb ($dt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', $inv)); return
    }
    if ($Value -is [System.DateTimeOffset]) {
        Add-ADHDJsonString $Sb (([System.DateTimeOffset]$Value).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', $inv)); return
    }
    if ($Value -is [timespan]) { [void]$Sb.Append(([timespan]$Value).TotalSeconds.ToString('R', $inv)); return }
    if ($Value -is [guid]) { Add-ADHDJsonString $Sb $Value.ToString(); return }
    if ($Value -is [enum]) { Add-ADHDJsonString $Sb $Value.ToString(); return }
    if ($Value -is [byte[]]) { Add-ADHDJsonString $Sb ([Convert]::ToBase64String([byte[]]$Value)); return }

    $typeName = $Value.GetType().FullName
    if ($typeName -eq 'System.Security.Principal.SecurityIdentifier') { Add-ADHDJsonString $Sb $Value.Value; return }
    if ($typeName -eq 'System.DirectoryServices.ActiveDirectorySecurity') {
        Add-ADHDJson -Sb $Sb -Value (Convert-ADHDSecurityDescriptor $Value) -Depth ($Depth + 1) -Preserve $Preserve
        return
    }
    if ($Depth -ge 12) { Add-ADHDJsonString $Sb (Protect-ADHDText ([string]$Value)); return }

    if ($Value -is [System.Collections.IDictionary]) {
        [void]$Sb.Append('{')
        $first = $true
        foreach ($k in @($Value.Keys)) {
            $ks = [string]$k
            if ($script:ForbiddenKeys.Contains($ks)) { continue }
            if (-not $first) { [void]$Sb.Append(',') }
            $first = $false
            Add-ADHDJsonString $Sb $ks
            [void]$Sb.Append(':')
            $pt = $PreserveThis -or ($null -ne $Preserve -and $Preserve.Contains($ks))
            Add-ADHDJson -Sb $Sb -Value $Value[$k] -Depth ($Depth + 1) -Preserve $Preserve -PreserveThis $pt
        }
        [void]$Sb.Append('}')
        return
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        [void]$Sb.Append('{')
        $first = $true
        foreach ($p in $Value.PSObject.Properties) {
            if ($script:ForbiddenKeys.Contains($p.Name)) { continue }
            if (-not $first) { [void]$Sb.Append(',') }
            $first = $false
            Add-ADHDJsonString $Sb $p.Name
            [void]$Sb.Append(':')
            $pt = $PreserveThis -or ($null -ne $Preserve -and $Preserve.Contains($p.Name))
            Add-ADHDJson -Sb $Sb -Value $p.Value -Depth ($Depth + 1) -Preserve $Preserve -PreserveThis $pt
        }
        [void]$Sb.Append('}')
        return
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        [void]$Sb.Append('[')
        $first = $true
        foreach ($item in $Value) {
            if (-not $first) { [void]$Sb.Append(',') }
            $first = $false
            Add-ADHDJson -Sb $Sb -Value $item -Depth ($Depth + 1) -Preserve $Preserve -PreserveThis $PreserveThis
        }
        [void]$Sb.Append(']')
        return
    }
    # 其他 .NET 物件（例如 ADSync cmdlet 輸出）：展開可讀屬性，深度限制 6
    if ($Depth -ge 6) { Add-ADHDJsonString $Sb (Protect-ADHDText ([string]$Value)); return }
    [void]$Sb.Append('{')
    $first = $true
    foreach ($p in $Value.PSObject.Properties) {
        if (-not $p.IsGettable) { continue }
        if ($p.MemberType -notin @('Property', 'NoteProperty', 'AliasProperty')) { continue }
        if ($script:ForbiddenKeys.Contains($p.Name)) { continue }
        $pv = $null
        try { $pv = $p.Value } catch { $pv = $null }
        if (-not $first) { [void]$Sb.Append(',') }
        $first = $false
        Add-ADHDJsonString $Sb $p.Name
        [void]$Sb.Append(':')
        $pt = $PreserveThis -or ($null -ne $Preserve -and $Preserve.Contains($p.Name))
        Add-ADHDJson -Sb $Sb -Value $pv -Depth ($Depth + 1) -Preserve $Preserve -PreserveThis $pt
    }
    [void]$Sb.Append('}')
}

function ConvertTo-ADHDJson {
    param($Value, [string[]] $PreserveKeys = @())
    $sb = New-Object System.Text.StringBuilder
    $set = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $PreserveKeys) { [void]$set.Add($k) }
    Add-ADHDJson -Sb $sb -Value $Value -Depth 0 -Preserve $set
    return $sb.ToString()
}

# ===========================================================================
# Bundle / dataset 管理
# ===========================================================================
function Initialize-ADHDContext {
    param([string] $OutputRoot, [string] $Label)
    $root = Resolve-ADHDPath $OutputRoot
    if (-not (Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }
    $safeLabel = ($Label -replace '[^\w\-]', '_')
    if (-not $safeLabel) { $safeLabel = 'host' }
    $started = [DateTime]::UtcNow
    $name = 'ADHD-Collect-{0}-{1}' -f $safeLabel, $started.ToString('yyyyMMddTHHmmssZ')
    $out = Join-Path $root $name
    New-Item -ItemType Directory -Path $out -Force | Out-Null

    $ci = [System.StringComparer]::OrdinalIgnoreCase
    $script:Ctx = @{
        BundleName     = $name
        Label          = $safeLabel
        OutDir         = $out
        OutputRoot     = $root
        StartedUtc     = $started
        LogPath        = Join-Path $out 'collection.log'
        Datasets       = New-Object System.Collections.Generic.List[object]
        Warnings       = New-Object System.Collections.Generic.List[string]
        ModuleVersions = [ordered]@{}
        Pseudo         = $false
        Hmac           = $null
        KeyId          = $null
        KeyFile        = $null
        PiiMap         = New-Object 'System.Collections.Generic.Dictionary[string,string]' -ArgumentList $ci
        PiiReverse     = New-Object 'System.Collections.Generic.Dictionary[string,string]' -ArgumentList ([System.StringComparer]::Ordinal)
        DnToSid        = New-Object 'System.Collections.Generic.Dictionary[string,string]' -ArgumentList $ci
        ADParams       = @{}
        AD             = $null
        GuidMap        = $null
        GraphConnected = $false
        ADInitError    = $null
        Entra          = @{
            TenantId         = $null
            Account          = $null
            Scopes           = @()
            GroupIds         = New-Object 'System.Collections.Generic.Dictionary[string,bool]' -ArgumentList $ci
            ReferencedGroups = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList $ci
            PrincipalIds     = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList $ci
            ResourceIds      = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList $ci
            Applications     = New-Object System.Collections.Generic.List[object]
            ServicePrincipals = New-Object System.Collections.Generic.List[object]
            AdminUnits       = New-Object System.Collections.Generic.List[string]
        }
    }
}

function Add-ADHDDatasetEntry {
    param([System.Collections.IDictionary] $Entry)
    $script:Ctx.Datasets.Add($Entry)
}

function Add-ADHDSkipped {
    param([string] $Name, [string] $Module, [string] $Reason)
    Add-ADHDDatasetEntry ([ordered]@{
        name = $Name; module = $Module; file = $null; format = 'jsonl'; records = 0; sha256 = $null
        status = 'skipped'; message = $Reason; startedUtc = [DateTime]::UtcNow; durationSec = 0
    })
    Write-ADHDLog "略過 $Name：$Reason" 'WARN'
}

function Export-ADHDDataset {
    param(
        [Parameter(Mandatory = $true)] [string] $Name,
        [Parameter(Mandatory = $true)] [string] $Module,
        [Parameter(Mandatory = $true)] [scriptblock] $Collector,
        [string[]] $PreserveKeys = @()
    )
    $__dsFile = "$Name.jsonl"
    $__dsPath = Join-Path $script:Ctx.OutDir $__dsFile
    $__dsPreserve = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($__k in $PreserveKeys) { [void]$__dsPreserve.Add($__k) }
    $__dsEntry = [ordered]@{
        name = $Name; module = $Module; file = $__dsFile; format = 'jsonl'; records = 0; sha256 = $null
        status = 'ok'; message = $null; startedUtc = [DateTime]::UtcNow; durationSec = 0
    }
    $__dsWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $__dsWriter = New-Object System.IO.StreamWriter -ArgumentList $__dsPath, $false, $script:Utf8NoBom
    $__dsSb = New-Object System.Text.StringBuilder
    $__dsCount = 0
    Write-ADHDLog "收集 $Name ..."
    try {
        $ErrorActionPreference = 'Stop'
        & $Collector | ForEach-Object {
            if ($null -ne $_) {
                [void]$__dsSb.Clear()
                Add-ADHDJson -Sb $__dsSb -Value $_ -Depth 0 -Preserve $__dsPreserve
                $__dsWriter.WriteLine($__dsSb.ToString())
                $__dsCount++
            }
        }
    }
    catch {
        $__dsEntry.status = $(if ($__dsCount -gt 0) { 'partial' } else { 'error' })
        $__dsEntry.message = Protect-ADHDText $_.Exception.Message
        Write-ADHDLog ("{0} 失敗（{1}）：{2}" -f $Name, $__dsEntry.status, $_.Exception.Message) 'WARN'
    }
    finally {
        $__dsWriter.Dispose()
    }
    $__dsWatch.Stop()
    $__dsEntry.records = $__dsCount
    $__dsEntry.durationSec = [math]::Round($__dsWatch.Elapsed.TotalSeconds, 2)
    $__dsEntry.sha256 = (Get-FileHash -LiteralPath $__dsPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Add-ADHDDatasetEntry $__dsEntry
    Write-ADHDLog ("{0}: {1} 筆，{2} 秒，狀態 {3}" -f $Name, $__dsCount, $__dsEntry.durationSec, $__dsEntry.status)
}

function Add-ADHDDirectoryDataset {
    param([string] $Name, [string] $Module, [string] $RelativeDir, [string] $Status = 'ok', [string] $Message)
    $dir = Join-Path $script:Ctx.OutDir $RelativeDir
    $files = New-Object System.Collections.Generic.List[object]
    if (Test-Path -LiteralPath $dir) {
        $base = (Resolve-Path -LiteralPath $script:Ctx.OutDir).ProviderPath.TrimEnd('\', '/')
        foreach ($f in (Get-ChildItem -LiteralPath $dir -Recurse -File | Sort-Object FullName)) {
            $rel = $f.FullName.Substring($base.Length + 1).Replace('\', '/')
            $files.Add([ordered]@{
                path   = $rel
                bytes  = $f.Length
                sha256 = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            })
        }
    }
    Add-ADHDDatasetEntry ([ordered]@{
        name = $Name; module = $Module; file = $RelativeDir; format = 'dir'; records = $files.Count; sha256 = $null
        status = $Status; message = $Message; startedUtc = [DateTime]::UtcNow; durationSec = 0; files = $files
    })
    Write-ADHDLog ("{0}: {1} 個檔案，狀態 {2}" -f $Name, $files.Count, $Status)
}

# ===========================================================================
# AD：共用
# ===========================================================================
function Initialize-ADHDAdContext {
    if (-not (Test-ADHDModule 'ActiveDirectory')) {
        $script:Ctx.ADInitError = '找不到 ActiveDirectory 模組（請安裝 RSAT: Active Directory module）'
        Write-ADHDLog ($script:Ctx.ADInitError + '。') 'WARN'
        return $false
    }
    try {
        Import-ADHDModule 'ActiveDirectory'
        $p = @{}
        if ($script:Opt.Server) { $p.Server = $script:Opt.Server }
        if ($script:Opt.Credential) { $p.Credential = $script:Opt.Credential }
        $dom = Get-ADDomain @p -ErrorAction Stop
        $rootDse = Get-ADRootDSE @p -ErrorAction Stop
        $forest = Get-ADForest @p -ErrorAction Stop
        if (-not $p.ContainsKey('Server')) { $p.Server = [string]$dom.PDCEmulator }
        $script:Ctx.ADParams = $p
        $script:Ctx.AD = @{
            Domain    = $dom
            Forest    = $forest
            DomainDN  = [string]$dom.DistinguishedName
            DomainDns = [string]$dom.DNSRoot
            NetBIOS   = [string]$dom.NetBIOSName
            DomainSid = [string]$dom.DomainSID
            ConfigNC  = [string]$rootDse.configurationNamingContext
            SchemaNC  = [string]$rootDse.schemaNamingContext
            ForestName = [string]$forest.Name
            Attr      = $null
        }
        $script:Ctx.AD.Attr = Get-ADHDSchemaAttributes @(
            'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'msDS-SupportedEncryptionTypes',
            'msDS-KeyCredentialLink', 'mS-DS-ConsistencyGuid', 'altSecurityIdentities',
            'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-PasswordExpirationTime'
        )
        Write-ADHDLog ("AD 目標：{0}（{1}），查詢 DC：{2}" -f $script:Ctx.AD.DomainDns, $script:Ctx.AD.DomainSid, $p.Server)
        return $true
    }
    catch {
        $script:Ctx.ADInitError = Protect-ADHDText $_.Exception.Message
        Write-ADHDLog ("AD 初始化失敗：" + $_.Exception.Message) 'ERROR'
        return $false
    }
}

function Get-ADHDSchemaAttributes {
    param([string[]] $Names)
    $set = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    $p = $script:Ctx.ADParams
    $filter = '(|' + (($Names | ForEach-Object { "(lDAPDisplayName=$_)" }) -join '') + ')'
    foreach ($o in (Get-ADObject -SearchBase $script:Ctx.AD.SchemaNC -LDAPFilter $filter -Properties lDAPDisplayName @p)) {
        [void]$set.Add([string]$o.lDAPDisplayName)
    }
    return , $set
}

function Select-ADHDAttributes {
    param([string[]] $Always, [string[]] $Optional)
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($a in $Always) { $list.Add($a) }
    foreach ($a in $Optional) { if ($script:Ctx.AD.Attr.Contains($a)) { $list.Add($a) } }
    return , $list.ToArray()
}

function Get-ADHDProp {
    param($Object, [string] $Name)
    if ($null -eq $Object) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    $v = $prop.Value
    # 集合（含 byte[]、ADPropertyValueCollection）原樣回傳，避免被 pipeline 展開
    if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string] -and $v -isnot [System.Collections.IDictionary]) { return , $v }
    return $v
}

function Get-ADHDSdPrincipalSids {
    param($Sd)
    if ($null -eq $Sd) { return , @() }
    if ($Sd.GetType().FullName -ne 'System.DirectoryServices.ActiveDirectorySecurity') { return , @() }
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($r in $Sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ([string]$r.AccessControlType -eq 'Allow') { [void]$set.Add($r.IdentityReference.Value) }
    }
    return , @($set)
}

function Resolve-ADHDMemberDns {
    param($Dns)
    $list = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Dns) { return , $list.ToArray() }
    foreach ($dn in $Dns) {
        $s = [string]$dn
        $sid = $null
        if ($script:Ctx.DnToSid.TryGetValue($s, [ref]$sid)) { $list.Add($sid); continue }
        if ($s -match '^CN=(S-1-[\d-]+),CN=ForeignSecurityPrincipals,') { $list.Add($Matches[1]); continue }
        $list.Add('DN:' + $s)
    }
    return , $list.ToArray()
}

function Register-ADHDAdUser {
    param($User)
    $sid = [string]$User.SID
    if ($User.DistinguishedName) { $script:Ctx.DnToSid[[string]$User.DistinguishedName] = $sid }
    if (Test-ADHDBuiltinSid $sid) { return }
    if (Test-ADHDInfraAccount ([string]$User.SamAccountName)) { return }
    Register-ADHDPii @($User.SamAccountName, $User.UserPrincipalName, $User.Name, (Get-ADHDProp $User 'DisplayName'),
        (Get-ADHDProp $User 'mail'), $User.GivenName, $User.Surname)
}

function Register-ADHDAdUserPii {
    # 未執行 AD 模組時的輕量登錄，確保其他模組輸出中的使用者識別資訊也會被假名化
    if (-not $script:Ctx.Pseudo) { return }
    $p = $script:Ctx.ADParams
    try {
        foreach ($u in (Get-ADUser -Filter * -Properties displayName, mail, userPrincipalName -ResultPageSize 1000 @p)) { Register-ADHDAdUser $u }
        Write-ADHDLog ("已登錄 {0} 筆 AD 使用者假名" -f $script:Ctx.PiiMap.Count)
    }
    catch { Write-ADHDLog ("AD 使用者假名登錄失敗：" + $_.Exception.Message) 'WARN' }
}

function Register-ADHDEntraUserPii {
    # 未執行 Entra 模組、但要收集 EntraLogs / SecurityAlerts 時：先登錄 Entra 使用者的顯示名稱與帳號，
    # 讓登入紀錄的 userDisplayName、告警標題中的名稱也被假名化（UPN / email 另有規則處理）
    if (-not $script:Ctx.Pseudo -or $script:Ctx.EntraPiiDone) { return }
    $script:Ctx.EntraPiiDone = $true
    try {
        $n = 0
        Invoke-ADHDGraphCollection -Uri 'v1.0/users?$top=999&$select=userPrincipalName,displayName,mail,givenName,surname,onPremisesSamAccountName' |
            ForEach-Object {
                Register-ADHDPii @($_.userPrincipalName, $_.displayName, $_.mail, $_.givenName, $_.surname, $_.onPremisesSamAccountName)
                $n++
            }
        Write-ADHDLog ("已登錄 {0} 個 Entra 使用者的假名" -f $n)
    }
    catch { Write-ADHDLog ("Entra 使用者假名登錄失敗，紀錄中的顯示名稱可能未假名化：" + $_.Exception.Message) 'WARN' }
}

# ===========================================================================
# 模組：AD
# ===========================================================================
function Invoke-ADHDModuleAD {
    $p = $script:Ctx.ADParams
    $ad = $script:Ctx.AD

    Export-ADHDDataset -Name 'ad_forest' -Module 'AD' -Collector {
        $f = $ad.Forest
        $schemaVer = $null
        try { $schemaVer = (Get-ADObject -Identity $ad.SchemaNC -Properties objectVersion @p).objectVersion } catch { }
        $features = New-Object System.Collections.Generic.List[object]
        try {
            foreach ($of in (Get-ADOptionalFeature -Filter * @p)) {
                $features.Add([ordered]@{ name = [string]$of.Name; enabled = ((Get-ADHDCount $of.EnabledScopes) -gt 0) })
            }
        } catch { Write-ADHDLog ("Optional features 讀取失敗：" + $_.Exception.Message) 'WARN' }
        [ordered]@{
            name               = [string]$f.Name
            rootDomain         = [string]$f.RootDomain
            forestMode         = [string]$f.ForestMode
            domains            = (ConvertTo-ADHDArray $f.Domains)
            globalCatalogs     = (ConvertTo-ADHDArray $f.GlobalCatalogs)
            sites              = (ConvertTo-ADHDArray $f.Sites)
            upnSuffixes        = (ConvertTo-ADHDArray $f.UPNSuffixes)
            spnSuffixes        = (ConvertTo-ADHDArray $f.SPNSuffixes)
            schemaMaster       = [string]$f.SchemaMaster
            domainNamingMaster = [string]$f.DomainNamingMaster
            schemaVersion      = $schemaVer
            optionalFeatures   = $features
        }
    }

    Export-ADHDDataset -Name 'ad_domain' -Module 'AD' -Collector {
        $d = $ad.Domain
        $obj = Get-ADObject -Identity $ad.DomainDN -Properties 'ms-DS-MachineAccountQuota' @p
        $dsh = $null
        try { $dsh = (Get-ADObject -Identity ("CN=Directory Service,CN=Windows NT,CN=Services," + $ad.ConfigNC) -Properties dSHeuristics @p).dSHeuristics } catch { }
        $krbtgt = $null
        try { $krbtgt = Get-ADUser -Identity 'krbtgt' -Properties pwdLastSet @p } catch { }
        [ordered]@{
            dnsRoot                 = $ad.DomainDns
            netBIOSName             = $ad.NetBIOS
            distinguishedName       = $ad.DomainDN
            domainSid               = $ad.DomainSid
            forest                  = $ad.ForestName
            domainMode              = [string]$d.DomainMode
            pdcEmulator             = [string]$d.PDCEmulator
            ridMaster               = [string]$d.RIDMaster
            infrastructureMaster    = [string]$d.InfrastructureMaster
            parentDomain            = [string]$d.ParentDomain
            childDomains            = (ConvertTo-ADHDArray $d.ChildDomains)
            machineAccountQuota     = (Get-ADHDProp $obj 'ms-DS-MachineAccountQuota')
            dsHeuristics            = $dsh
            krbtgtPwdLastSet        = (ConvertFrom-ADHDFileTime (Get-ADHDProp $krbtgt 'pwdLastSet'))
            lapsLegacySchema        = $ad.Attr.Contains('ms-Mcs-AdmPwdExpirationTime')
            lapsWindowsSchema       = $ad.Attr.Contains('msLAPS-PasswordExpirationTime')
            keyCredentialLinkSchema = $ad.Attr.Contains('msDS-KeyCredentialLink')
            queriedDc               = [string]$p.Server
        }
    }

    Export-ADHDDataset -Name 'ad_password_policies' -Module 'AD' -Collector {
        $dp = Get-ADDefaultDomainPasswordPolicy @p
        [ordered]@{
            kind = 'default'; name = 'Default Domain Policy'; precedence = $null; appliesTo = @()
            complexityEnabled = [bool]$dp.ComplexityEnabled; minPasswordLength = $dp.MinPasswordLength
            passwordHistoryCount = $dp.PasswordHistoryCount; maxPasswordAge = $dp.MaxPasswordAge; minPasswordAge = $dp.MinPasswordAge
            lockoutThreshold = $dp.LockoutThreshold; lockoutDuration = $dp.LockoutDuration
            lockoutObservationWindow = $dp.LockoutObservationWindow; reversibleEncryptionEnabled = [bool]$dp.ReversibleEncryptionEnabled
        }
        # FGPP 預設只有 Domain Admins 可讀；讀不到時只記錄警告
        try {
            foreach ($f in (Get-ADFineGrainedPasswordPolicy -Filter * @p)) {
                [ordered]@{
                    kind = 'fgpp'; name = [string]$f.Name; precedence = $f.Precedence; appliesTo = (ConvertTo-ADHDArray $f.AppliesTo)
                    complexityEnabled = [bool]$f.ComplexityEnabled; minPasswordLength = $f.MinPasswordLength
                    passwordHistoryCount = $f.PasswordHistoryCount; maxPasswordAge = $f.MaxPasswordAge; minPasswordAge = $f.MinPasswordAge
                    lockoutThreshold = $f.LockoutThreshold; lockoutDuration = $f.LockoutDuration
                    lockoutObservationWindow = $f.LockoutObservationWindow; reversibleEncryptionEnabled = [bool]$f.ReversibleEncryptionEnabled
                }
            }
        } catch { Write-ADHDLog ("FGPP 讀取失敗（通常需要 Domain Admins 權限）：" + $_.Exception.Message) 'WARN' }
    }

    Export-ADHDDataset -Name 'ad_trusts' -Module 'AD' -PreserveKeys @('name', 'target', 'source', 'distinguishedName') -Collector {
        foreach ($t in (Get-ADTrust -Filter * @p)) {
            [ordered]@{
                name = [string]$t.Name; target = [string]$t.Target; source = [string]$t.Source
                distinguishedName = [string]$t.DistinguishedName
                direction = [string]$t.Direction; trustType = [string]$t.TrustType; trustAttributes = $t.TrustAttributes
                forestTransitive = [bool]$t.ForestTransitive; intraForest = [bool]$t.IntraForest
                selectiveAuthentication = [bool]$t.SelectiveAuthentication
                sidFilteringQuarantined = [bool]$t.SIDFilteringQuarantined; sidFilteringForestAware = [bool]$t.SIDFilteringForestAware
                tgtDelegation = [bool]$t.TGTDelegation; disallowTransivity = [bool]$t.DisallowTransivity
                usesAESKeys = [bool]$t.UsesAESKeys; usesRC4Encryption = [bool]$t.UsesRC4Encryption
                whenCreated = (Get-ADHDProp $t 'whenCreated')
            }
        }
    }

    Export-ADHDDataset -Name 'ad_domain_controllers' -Module 'AD' -PreserveKeys @('name', 'hostName', 'computerObjectDN') -Collector {
        foreach ($dc in (Get-ADDomainController -Filter * @p)) {
            [ordered]@{
                name = [string]$dc.Name; hostName = [string]$dc.HostName; ipv4Address = [string]$dc.IPv4Address
                site = [string]$dc.Site; domain = [string]$dc.Domain
                operatingSystem = [string]$dc.OperatingSystem; operatingSystemVersion = [string]$dc.OperatingSystemVersion
                isGlobalCatalog = [bool]$dc.IsGlobalCatalog; isReadOnly = [bool]$dc.IsReadOnly
                operationMasterRoles = (ConvertTo-ADHDStringArray $dc.OperationMasterRoles)
                computerObjectDN = [string]$dc.ComputerObjectDN; enabled = [bool]$dc.Enabled
            }
        }
    }

    Export-ADHDDataset -Name 'ad_ous' -Module 'AD' -PreserveKeys @('name', 'distinguishedName') -Collector {
        $root = Get-ADObject -Identity $ad.DomainDN -Properties gPLink, gPOptions, whenCreated @p
        [ordered]@{
            objectClass = 'domainDNS'; name = $ad.DomainDns; distinguishedName = $ad.DomainDN
            gpLinks = (ConvertFrom-ADHDGpLink ([string](Get-ADHDProp $root 'gPLink')))
            blockInheritance = ([int](Get-ADHDProp $root 'gPOptions') -eq 1)
            protectedFromAccidentalDeletion = $null; whenCreated = (Get-ADHDProp $root 'whenCreated'); descriptionHasSecretHint = $false
        }
        foreach ($ou in (Get-ADOrganizationalUnit -Filter * -Properties gPLink, gPOptions, description, whenCreated, ProtectedFromAccidentalDeletion -ResultPageSize 500 @p)) {
            [ordered]@{
                objectClass = 'organizationalUnit'; name = [string]$ou.Name; distinguishedName = [string]$ou.DistinguishedName
                gpLinks = (ConvertFrom-ADHDGpLink ([string](Get-ADHDProp $ou 'gPLink')))
                blockInheritance = ([int](Get-ADHDProp $ou 'gPOptions') -eq 1)
                protectedFromAccidentalDeletion = [bool](Get-ADHDProp $ou 'ProtectedFromAccidentalDeletion')
                whenCreated = (Get-ADHDProp $ou 'whenCreated')
                descriptionHasSecretHint = (Test-ADHDSecretHint ([string](Get-ADHDProp $ou 'description')))
            }
        }
    }

    # 先抓群組建立 DN→SID 對照（群組成員解析需要），最後才輸出群組
    $script:ADHDGroupsCache = @()
    try {
        $script:ADHDGroupsCache = @(Get-ADGroup -Filter * -Properties member, adminCount, managedBy, description, whenCreated -ResultPageSize 500 @p)
        foreach ($g in $script:ADHDGroupsCache) { $script:Ctx.DnToSid[[string]$g.DistinguishedName] = [string]$g.SID }
    }
    catch { Write-ADHDLog ("群組清單讀取失敗：" + $_.Exception.Message) 'WARN' }

    $userAttrs = Select-ADHDAttributes -Always @(
        'adminCount', 'description', 'info', 'displayName', 'mail', 'userPrincipalName', 'servicePrincipalName',
        'userAccountControl', 'pwdLastSet', 'lastLogonTimestamp', 'whenCreated', 'whenChanged', 'primaryGroupID',
        'sIDHistory', 'accountExpires', 'department', 'title', 'scriptPath', 'givenName', 'sn'
    ) -Optional @(
        'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'msDS-SupportedEncryptionTypes',
        'msDS-KeyCredentialLink', 'mS-DS-ConsistencyGuid', 'altSecurityIdentities'
    )
    Export-ADHDDataset -Name 'ad_users' -Module 'AD' -PreserveKeys @('department', 'title') -Collector {
        foreach ($u in (Get-ADUser -Filter * -Properties $userAttrs -ResultPageSize 500 @p)) {
            Register-ADHDAdUser $u
            $sid = [string]$u.SID
            $uac = [int](Get-ADHDProp $u 'userAccountControl')
            $pls = Get-ADHDProp $u 'pwdLastSet'
            [ordered]@{
                objectClass               = 'user'
                sid                       = $sid
                objectGuid                = [string]$u.ObjectGUID
                samAccountName            = [string]$u.SamAccountName
                userPrincipalName         = [string]$u.UserPrincipalName
                name                      = [string]$u.Name
                displayName               = (Get-ADHDProp $u 'displayName')
                givenName                 = [string]$u.GivenName
                surname                   = [string]$u.Surname
                mail                      = (Get-ADHDProp $u 'mail')
                distinguishedName         = [string]$u.DistinguishedName
                enabled                   = [bool]$u.Enabled
                isBuiltin                 = (Test-ADHDBuiltinSid $sid)
                userAccountControl        = $uac
                uacFlags                  = (Get-ADHDUacFlags $uac)
                adminCount                = (Get-ADHDProp $u 'adminCount')
                primaryGroupId            = (Get-ADHDProp $u 'primaryGroupID')
                servicePrincipalNames     = (ConvertTo-ADHDArray (Get-ADHDProp $u 'servicePrincipalName'))
                sidHistory                = (ConvertTo-ADHDStringArray (Get-ADHDProp $u 'sIDHistory'))
                pwdLastSet                = (ConvertFrom-ADHDFileTime $pls)
                mustChangePassword        = ($null -ne $pls -and [string]$pls -eq '0')
                lastLogonTimestamp        = (ConvertFrom-ADHDFileTime (Get-ADHDProp $u 'lastLogonTimestamp'))
                accountExpires            = (ConvertFrom-ADHDFileTime (Get-ADHDProp $u 'accountExpires'))
                whenCreated               = (Get-ADHDProp $u 'whenCreated')
                whenChanged               = (Get-ADHDProp $u 'whenChanged')
                allowedToDelegateTo       = (ConvertTo-ADHDArray (Get-ADHDProp $u 'msDS-AllowedToDelegateTo'))
                rbcdAllowedPrincipals     = (Get-ADHDSdPrincipalSids (Get-ADHDProp $u 'msDS-AllowedToActOnBehalfOfOtherIdentity'))
                supportedEncryptionTypes  = (Get-ADHDProp $u 'msDS-SupportedEncryptionTypes')
                keyCredentialLinkCount    = (Get-ADHDCount (Get-ADHDProp $u 'msDS-KeyCredentialLink'))
                altSecurityIdentitiesCount = (Get-ADHDCount (Get-ADHDProp $u 'altSecurityIdentities'))
                consistencyGuid           = (ConvertTo-ADHDGuidString (Get-ADHDProp $u 'mS-DS-ConsistencyGuid'))
                department                = (Get-ADHDProp $u 'department')
                title                     = (Get-ADHDProp $u 'title')
                scriptPath                = (Get-ADHDProp $u 'scriptPath')
                descriptionHasSecretHint  = (Test-ADHDSecretHint ([string](Get-ADHDProp $u 'description')))
                infoHasSecretHint         = (Test-ADHDSecretHint ([string](Get-ADHDProp $u 'info')))
            }
        }
    }

    $computerAttrs = Select-ADHDAttributes -Always @(
        'dNSHostName', 'operatingSystem', 'operatingSystemVersion', 'userAccountControl', 'pwdLastSet', 'lastLogonTimestamp',
        'whenCreated', 'servicePrincipalName', 'primaryGroupID', 'description', 'managedBy', 'sIDHistory'
    ) -Optional @(
        'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'msDS-SupportedEncryptionTypes',
        'msDS-KeyCredentialLink', 'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-PasswordExpirationTime'
    )
    Export-ADHDDataset -Name 'ad_computers' -Module 'AD' -PreserveKeys @('name', 'samAccountName', 'dnsHostName', 'distinguishedName') -Collector {
        foreach ($c in (Get-ADComputer -Filter * -Properties $computerAttrs -ResultPageSize 500 @p)) {
            $sid = [string]$c.SID
            $script:Ctx.DnToSid[[string]$c.DistinguishedName] = $sid
            $uac = [int](Get-ADHDProp $c 'userAccountControl')
            $pg = [int](Get-ADHDProp $c 'primaryGroupID')
            $lapsLegacy = ConvertFrom-ADHDFileTime (Get-ADHDProp $c 'ms-Mcs-AdmPwdExpirationTime')
            $lapsWindows = ConvertFrom-ADHDFileTime (Get-ADHDProp $c 'msLAPS-PasswordExpirationTime')
            [ordered]@{
                objectClass              = 'computer'
                sid                      = $sid
                objectGuid               = [string]$c.ObjectGUID
                name                     = [string]$c.Name
                samAccountName           = [string]$c.SamAccountName
                dnsHostName              = (Get-ADHDProp $c 'dNSHostName')
                distinguishedName        = [string]$c.DistinguishedName
                enabled                  = [bool]$c.Enabled
                operatingSystem          = (Get-ADHDProp $c 'operatingSystem')
                operatingSystemVersion   = (Get-ADHDProp $c 'operatingSystemVersion')
                userAccountControl       = $uac
                uacFlags                 = (Get-ADHDUacFlags $uac)
                primaryGroupId           = $pg
                isDomainController       = ($pg -eq 516 -or $pg -eq 521 -or (($uac -band 0x2000) -ne 0))
                isReadOnlyDC             = ($pg -eq 521)
                pwdLastSet               = (ConvertFrom-ADHDFileTime (Get-ADHDProp $c 'pwdLastSet'))
                lastLogonTimestamp       = (ConvertFrom-ADHDFileTime (Get-ADHDProp $c 'lastLogonTimestamp'))
                whenCreated              = (Get-ADHDProp $c 'whenCreated')
                servicePrincipalNames    = (ConvertTo-ADHDArray (Get-ADHDProp $c 'servicePrincipalName'))
                allowedToDelegateTo      = (ConvertTo-ADHDArray (Get-ADHDProp $c 'msDS-AllowedToDelegateTo'))
                rbcdAllowedPrincipals    = (Get-ADHDSdPrincipalSids (Get-ADHDProp $c 'msDS-AllowedToActOnBehalfOfOtherIdentity'))
                supportedEncryptionTypes = (Get-ADHDProp $c 'msDS-SupportedEncryptionTypes')
                keyCredentialLinkCount   = (Get-ADHDCount (Get-ADHDProp $c 'msDS-KeyCredentialLink'))
                lapsLegacyExpiration     = $lapsLegacy
                lapsWindowsExpiration    = $lapsWindows
                hasLaps                  = ($null -ne $lapsLegacy -or $null -ne $lapsWindows)
                managedBy                = (Get-ADHDProp $c 'managedBy')
                sidHistory               = (ConvertTo-ADHDStringArray (Get-ADHDProp $c 'sIDHistory'))
                descriptionHasSecretHint = (Test-ADHDSecretHint ([string](Get-ADHDProp $c 'description')))
            }
        }
    }

    Export-ADHDDataset -Name 'ad_service_accounts' -Module 'AD' -PreserveKeys @('name', 'samAccountName', 'distinguishedName') -Collector {
        $saAttrs = @('servicePrincipalName', 'PrincipalsAllowedToRetrieveManagedPassword', 'PrincipalsAllowedToDelegateToAccount',
            'userAccountControl', 'pwdLastSet', 'lastLogonTimestamp', 'whenCreated', 'description')
        foreach ($s in (Get-ADServiceAccount -Filter * -Properties $saAttrs @p)) {
            $sid = [string]$s.SID
            $script:Ctx.DnToSid[[string]$s.DistinguishedName] = $sid
            $uac = [int](Get-ADHDProp $s 'userAccountControl')
            [ordered]@{
                objectClass                       = [string]$s.ObjectClass
                sid                               = $sid
                name                              = [string]$s.Name
                samAccountName                    = [string]$s.SamAccountName
                distinguishedName                 = [string]$s.DistinguishedName
                enabled                           = [bool]$s.Enabled
                userAccountControl                = $uac
                uacFlags                          = (Get-ADHDUacFlags $uac)
                servicePrincipalNames             = (ConvertTo-ADHDArray (Get-ADHDProp $s 'servicePrincipalName'))
                principalsAllowedToRetrievePassword = (Resolve-ADHDMemberDns (Get-ADHDProp $s 'PrincipalsAllowedToRetrieveManagedPassword'))
                principalsAllowedToDelegate       = (Resolve-ADHDMemberDns (Get-ADHDProp $s 'PrincipalsAllowedToDelegateToAccount'))
                pwdLastSet                        = (ConvertFrom-ADHDFileTime (Get-ADHDProp $s 'pwdLastSet'))
                lastLogonTimestamp                = (ConvertFrom-ADHDFileTime (Get-ADHDProp $s 'lastLogonTimestamp'))
                whenCreated                       = (Get-ADHDProp $s 'whenCreated')
                descriptionHasSecretHint          = (Test-ADHDSecretHint ([string](Get-ADHDProp $s 'description')))
            }
        }
    }

    Export-ADHDDataset -Name 'ad_groups' -Module 'AD' -PreserveKeys @('name', 'samAccountName', 'distinguishedName') -Collector {
        foreach ($g in $script:ADHDGroupsCache) {
            $sid = [string]$g.SID
            $members = Resolve-ADHDMemberDns (Get-ADHDProp $g 'member')
            [ordered]@{
                objectClass              = 'group'
                sid                      = $sid
                objectGuid               = [string]$g.ObjectGUID
                name                     = [string]$g.Name
                samAccountName           = [string]$g.SamAccountName
                distinguishedName        = [string]$g.DistinguishedName
                groupScope               = [string]$g.GroupScope
                groupCategory            = [string]$g.GroupCategory
                isBuiltin                = (Test-ADHDBuiltinSid $sid)
                adminCount               = (Get-ADHDProp $g 'adminCount')
                managedBy                = (Get-ADHDProp $g 'managedBy')
                whenCreated              = (Get-ADHDProp $g 'whenCreated')
                memberCount              = $members.Count
                members                  = $members
                descriptionHasSecretHint = (Test-ADHDSecretHint ([string](Get-ADHDProp $g 'description')))
            }
        }
    }
    $script:ADHDGroupsCache = $null
}

# ===========================================================================
# 模組：ADACL
# ===========================================================================
function Initialize-ADHDGuidMap {
    if ($null -ne $script:Ctx.GuidMap) { return }
    $p = $script:Ctx.ADParams
    $map = New-Object 'System.Collections.Generic.Dictionary[guid,object]'
    foreach ($o in (Get-ADObject -SearchBase $script:Ctx.AD.SchemaNC -LDAPFilter '(schemaIDGUID=*)' -Properties lDAPDisplayName, schemaIDGUID, objectClass -ResultPageSize 1000 @p)) {
        $bytes = Get-ADHDProp $o 'schemaIDGUID'
        if ($bytes -isnot [byte[]]) { continue }
        $g = [guid]::new([byte[]]$bytes)
        $kind = $(if ([string]$o.ObjectClass -eq 'classSchema') { 'class' } else { 'attribute' })
        $map[$g] = [ordered]@{ guid = $g.ToString(); name = [string](Get-ADHDProp $o 'lDAPDisplayName'); kind = $kind }
    }
    $erBase = 'CN=Extended-Rights,' + $script:Ctx.AD.ConfigNC
    foreach ($o in (Get-ADObject -SearchBase $erBase -LDAPFilter '(objectClass=controlAccessRight)' -Properties rightsGuid, validAccesses -ResultPageSize 1000 @p)) {
        $rg = [string](Get-ADHDProp $o 'rightsGuid')
        $g = [guid]::Empty
        if (-not [guid]::TryParse($rg, [ref]$g)) { continue }
        $va = [int](Get-ADHDProp $o 'validAccesses')
        $kind = switch ($va) { 256 { 'extendedRight' } 48 { 'propertySet' } 8 { 'validatedWrite' } default { 'controlAccessRight' } }
        if (-not $map.ContainsKey($g)) { $map[$g] = [ordered]@{ guid = $g.ToString(); name = [string]$o.Name; kind = $kind } }
    }
    $script:Ctx.GuidMap = $map
    Write-ADHDLog ("GUID 對照表：{0} 筆" -f $map.Count)
}

function Resolve-ADHDGuidName {
    param($Guid)
    if ($null -eq $Guid) { return $null }
    $g = [guid]$Guid
    if ($g -eq [guid]::Empty) { return $null }
    $hit = $null
    if ($null -ne $script:Ctx.GuidMap -and $script:Ctx.GuidMap.TryGetValue($g, [ref]$hit)) { return $hit.name }
    return $null
}

function Convert-ADHDSecurityDescriptor {
    param($Sd)
    if ($null -eq $Sd) { return $null }
    $sidType = [System.Security.Principal.SecurityIdentifier]
    $owner = $null
    try { $owner = $Sd.GetOwner($sidType).Value } catch { }
    $aces = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Sd.GetAccessRules($true, $false, $sidType)) {
        $ot = [guid]$r.ObjectType
        $iot = [guid]$r.InheritedObjectType
        $aces.Add([ordered]@{
            principal               = $r.IdentityReference.Value
            type                    = [string]$r.AccessControlType
            rights                  = [string]$r.ActiveDirectoryRights
            objectType              = $(if ($ot -ne [guid]::Empty) { $ot.ToString() } else { $null })
            objectTypeName          = (Resolve-ADHDGuidName $ot)
            inheritedObjectType     = $(if ($iot -ne [guid]::Empty) { $iot.ToString() } else { $null })
            inheritedObjectTypeName = (Resolve-ADHDGuidName $iot)
            inheritanceType         = [string]$r.InheritanceType
        })
    }
    return [ordered]@{ owner = $owner; daclProtected = [bool]$Sd.AreAccessRulesProtected; aces = $aces }
}

function Invoke-ADHDModuleADACL {
    $p = $script:Ctx.ADParams
    $ad = $script:Ctx.AD
    try { Initialize-ADHDGuidMap }
    catch { Write-ADHDLog ("GUID 對照表建立失敗：" + $_.Exception.Message) 'WARN'; $script:Ctx.GuidMap = New-Object 'System.Collections.Generic.Dictionary[guid,object]' }

    Export-ADHDDataset -Name 'ad_guid_map' -Module 'ADACL' -PreserveKeys @('name') -Collector {
        foreach ($v in $script:Ctx.GuidMap.Values) { $v }
    }

    $dn = $ad.DomainDN
    $specialGroups = @('DnsAdmins', 'Group Policy Creator Owners', 'Cert Publishers', 'Key Admins', 'Enterprise Key Admins',
        'Protected Users', 'Exchange Windows Permissions', 'Exchange Trusted Subsystem', 'Organization Management')
    $queries = New-Object System.Collections.Generic.List[object]
    $queries.Add(@{ Tag = 'domainRoot'; Identity = $dn })
    $queries.Add(@{ Tag = 'adminSDHolder'; Identity = "CN=AdminSDHolder,CN=System,$dn" })
    $queries.Add(@{ Tag = 'ou'; Base = $dn; Scope = 'Subtree'; Filter = '(objectClass=organizationalUnit)' })
    $queries.Add(@{ Tag = 'container'; Base = $dn; Scope = 'OneLevel'; Filter = '(|(objectClass=container)(objectClass=builtinDomain))' })
    $queries.Add(@{ Tag = 'adminCount'; Base = $dn; Scope = 'Subtree'; Filter = '(adminCount=1)' })
    $queries.Add(@{ Tag = 'gpo'; Base = "CN=Policies,CN=System,$dn"; Scope = 'OneLevel'; Filter = '(objectClass=groupPolicyContainer)' })
    $queries.Add(@{ Tag = 'domainController'; Base = $dn; Scope = 'Subtree'; Filter = '(&(objectCategory=computer)(|(primaryGroupID=516)(primaryGroupID=521)))' })
    $queries.Add(@{ Tag = 'syncInfra'; Base = $dn; Scope = 'Subtree'; Filter = '(|(sAMAccountName=AZUREADSSOACC$)(sAMAccountName=MSOL_*)(sAMAccountName=Sync_*)(sAMAccountName=AAD_*)(sAMAccountName=provAgentgMSA*))' })
    $queries.Add(@{ Tag = 'specialGroup'; Base = $dn; Scope = 'Subtree'; Filter = '(&(objectCategory=group)(|' + (($specialGroups | ForEach-Object { "(sAMAccountName=$_)" }) -join '') + '))' })
    if ($script:Opt.FullAcl) {
        $queries.Add(@{ Tag = 'full'; Base = $dn; Scope = 'Subtree'; Filter = '(|(objectCategory=person)(objectCategory=group)(objectCategory=computer)(objectClass=msDS-GroupManagedServiceAccount))' })
    }

    Export-ADHDDataset -Name 'ad_acls' -Module 'ADACL' -Collector {
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
        $props = @('nTSecurityDescriptor', 'objectClass', 'objectSid', 'sAMAccountName')
        foreach ($q in $queries) {
            try {
                if ($q.Identity) { $objs = @(Get-ADObject -Identity $q.Identity -Properties $props @p) }
                else { $objs = @(Get-ADObject -SearchBase $q.Base -SearchScope $q.Scope -LDAPFilter $q.Filter -Properties $props -ResultPageSize 200 @p) }
            }
            catch {
                Write-ADHDLog ("ACL 查詢 {0} 失敗：{1}" -f $q.Tag, $_.Exception.Message) 'WARN'
                continue
            }
            foreach ($o in $objs) {
                if (-not $seen.Add([string]$o.DistinguishedName)) { continue }
                $sdInfo = Convert-ADHDSecurityDescriptor (Get-ADHDProp $o 'nTSecurityDescriptor')
                $sidVal = Get-ADHDProp $o 'objectSid'
                [ordered]@{
                    distinguishedName = [string]$o.DistinguishedName
                    objectClass       = [string]$o.ObjectClass
                    sid               = $(if ($null -ne $sidVal) { [string]$sidVal } else { $null })
                    samAccountName    = (Get-ADHDProp $o 'sAMAccountName')
                    reason            = $q.Tag
                    owner             = $(if ($sdInfo) { $sdInfo.owner } else { $null })
                    daclProtected     = $(if ($sdInfo) { $sdInfo.daclProtected } else { $null })
                    aces              = (Get-ADHDAces $sdInfo)
                }
            }
        }
    }
}

# ===========================================================================
# 模組：GPO
# ===========================================================================
function Invoke-ADHDModuleGPO {
    $ad = $script:Ctx.AD
    if (-not (Test-ADHDModule 'GroupPolicy')) {
        foreach ($n in 'ad_gpos', 'gpo_reports', 'gpo_gpp_cpassword') { Add-ADHDSkipped $n 'GPO' '找不到 GroupPolicy 模組（請安裝 RSAT: Group Policy Management Tools）' }
        return
    }
    Import-ADHDModule 'GroupPolicy'
    if ($script:Opt.Credential) { Write-ADHDLog 'GroupPolicy 模組與 SYSVOL 掃描不支援 -Credential，將使用目前登入身分。' 'WARN' }
    $gp = @{ Domain = $ad.DomainDns }
    if ($script:Ctx.ADParams.Server) { $gp.Server = $script:Ctx.ADParams.Server }

    $script:ADHDGpoCache = @()
    Export-ADHDDataset -Name 'ad_gpos' -Module 'GPO' -PreserveKeys @('displayName') -Collector {
        $script:ADHDGpoCache = @(Get-GPO -All @gp)
        foreach ($g in $script:ADHDGpoCache) {
            $wmi = Get-ADHDProp $g 'WmiFilter'
            [ordered]@{
                id                       = ([string]$g.Id).ToLowerInvariant()
                displayName              = [string]$g.DisplayName
                gpoStatus                = [string]$g.GpoStatus
                owner                    = [string]$g.Owner
                creationTime             = $g.CreationTime
                modificationTime         = $g.ModificationTime
                wmiFilter                = $(if ($wmi) { [string]$wmi.Name } else { $null })
                userVersionDs            = (Get-ADHDProp $g.User 'DSVersion')
                userVersionSysvol        = (Get-ADHDProp $g.User 'SysvolVersion')
                computerVersionDs        = (Get-ADHDProp $g.Computer 'DSVersion')
                computerVersionSysvol    = (Get-ADHDProp $g.Computer 'SysvolVersion')
                descriptionHasSecretHint = (Test-ADHDSecretHint ([string]$g.Description))
            }
        }
    }

    if ($script:Opt.SkipGpoXml) {
        Add-ADHDSkipped 'gpo_reports' 'GPO' '使用者指定 -SkipGpoXml'
    }
    else {
        $rel = 'gpo_reports'
        $dir = Join-Path $script:Ctx.OutDir $rel
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $failed = 0
        foreach ($g in $script:ADHDGpoCache) {
            try {
                $xml = Get-GPOReport -Guid $g.Id -ReportType Xml @gp -ErrorAction Stop
                $path = Join-Path $dir (([string]$g.Id).ToLowerInvariant() + '.xml')
                [System.IO.File]::WriteAllText($path, (Protect-ADHDText ([string]$xml)), $script:Utf8NoBom)
            }
            catch { $failed++; Write-ADHDLog ("GPO 報表 {0} 失敗：{1}" -f $g.Id, $_.Exception.Message) 'WARN' }
        }
        $status = $(if ($failed -eq 0) { 'ok' } elseif ($failed -lt (Get-ADHDCount $script:ADHDGpoCache)) { 'partial' } else { 'error' })
        if ((Get-ADHDCount $script:ADHDGpoCache) -eq 0) { $status = 'ok' }
        Add-ADHDDirectoryDataset -Name 'gpo_reports' -Module 'GPO' -RelativeDir $rel -Status $status -Message $(if ($failed) { "$failed 份報表失敗" } else { $null })
    }
    $script:ADHDGpoCache = $null

    Export-ADHDDataset -Name 'gpo_gpp_cpassword' -Module 'GPO' -Collector {
        $root = '\\{0}\SYSVOL\{0}\Policies' -f $ad.DomainDns
        if (-not (Test-Path -LiteralPath $root)) { throw "無法存取 SYSVOL：$root" }
        $names = @('Groups.xml', 'Services.xml', 'ScheduledTasks.xml', 'DataSources.xml', 'Printers.xml', 'Drives.xml')
        foreach ($f in (Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $names -contains $_.Name })) {
            $content = $null
            try { $content = [System.IO.File]::ReadAllText($f.FullName) } catch { continue }
            $hits = [regex]::Matches($content, 'cpassword="[^"]+"')
            if ($hits.Count -eq 0) { continue }
            $guid = [regex]::Match($f.FullName, '\{[0-9A-Fa-f\-]{36}\}').Value
            [ordered]@{
                gpoGuid          = $guid.Trim('{}').ToLowerInvariant()
                scope            = $(if ($f.FullName -match '\\Machine\\') { 'Machine' } elseif ($f.FullName -match '\\User\\') { 'User' } else { $null })
                file             = $f.FullName.Substring($root.Length).TrimStart('\')
                cpasswordPresent = $true
                occurrences      = $hits.Count
            }
        }
    }
}

# ===========================================================================
# 模組：ADCS
# ===========================================================================
function Invoke-ADHDModuleADCS {
    $p = $script:Ctx.ADParams
    $ad = $script:Ctx.AD
    try { Initialize-ADHDGuidMap } catch { Write-ADHDLog ("GUID 對照表建立失敗：" + $_.Exception.Message) 'WARN' }
    $pks = 'CN=Public Key Services,CN=Services,' + $ad.ConfigNC
    try { [void](Get-ADObject -Identity $pks @p) }
    catch {
        foreach ($n in 'adcs_containers', 'adcs_cas', 'adcs_templates') { Add-ADHDSkipped $n 'ADCS' "找不到 Public Key Services 容器：$($_.Exception.Message)" }
        return
    }

    Export-ADHDDataset -Name 'adcs_containers' -Module 'ADCS' -PreserveKeys @('name', 'distinguishedName') -Collector {
        $objs = @(Get-ADObject -Identity $pks -Properties nTSecurityDescriptor @p)
        $objs += @(Get-ADObject -SearchBase $pks -SearchScope OneLevel -LDAPFilter '(objectClass=*)' -Properties nTSecurityDescriptor, cACertificate @p)
        foreach ($o in $objs) {
            $sdInfo = Convert-ADHDSecurityDescriptor (Get-ADHDProp $o 'nTSecurityDescriptor')
            [ordered]@{
                name              = [string]$o.Name
                distinguishedName = [string]$o.DistinguishedName
                objectClass       = [string]$o.ObjectClass
                caCertificateCount = (Get-ADHDCount (Get-ADHDProp $o 'cACertificate'))
                owner             = $(if ($sdInfo) { $sdInfo.owner } else { $null })
                daclProtected     = $(if ($sdInfo) { $sdInfo.daclProtected } else { $null })
                aces              = (Get-ADHDAces $sdInfo)
            }
        }
    }

    $script:ADHDPublishedTemplates = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    Export-ADHDDataset -Name 'adcs_cas' -Module 'ADCS' -PreserveKeys @('name', 'displayName', 'dnsHostName', 'distinguishedName') -Collector {
        foreach ($ca in (Get-ADObject -SearchBase ("CN=Enrollment Services," + $pks) -SearchScope OneLevel -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties dNSHostName, certificateTemplates, flags, displayName, whenCreated, nTSecurityDescriptor @p)) {
            $tpls = ConvertTo-ADHDArray (Get-ADHDProp $ca 'certificateTemplates')
            foreach ($t in $tpls) { [void]$script:ADHDPublishedTemplates.Add([string]$t) }
            $sdInfo = Convert-ADHDSecurityDescriptor (Get-ADHDProp $ca 'nTSecurityDescriptor')
            [ordered]@{
                name                 = [string]$ca.Name
                displayName          = (Get-ADHDProp $ca 'displayName')
                dnsHostName          = (Get-ADHDProp $ca 'dNSHostName')
                distinguishedName    = [string]$ca.DistinguishedName
                flags                = (Get-ADHDProp $ca 'flags')
                certificateTemplates = $tpls
                whenCreated          = (Get-ADHDProp $ca 'whenCreated')
                owner                = $(if ($sdInfo) { $sdInfo.owner } else { $null })
                aces                 = (Get-ADHDAces $sdInfo)
            }
        }
    }

    Export-ADHDDataset -Name 'adcs_templates' -Module 'ADCS' -PreserveKeys @('name', 'displayName', 'distinguishedName') -Collector {
        $authEkus = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2', '2.5.29.37.0')
        $tplProps = @('displayName', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', 'pKIExtendedKeyUsage',
            'msPKI-Certificate-Application-Policy', 'msPKI-Template-Schema-Version', 'msPKI-Private-Key-Flag', 'revision', 'whenChanged', 'nTSecurityDescriptor')
        foreach ($t in (Get-ADObject -SearchBase ("CN=Certificate Templates," + $pks) -SearchScope OneLevel -LDAPFilter '(objectClass=pKICertificateTemplate)' -Properties $tplProps @p)) {
            $nameFlag = [int](Get-ADHDProp $t 'msPKI-Certificate-Name-Flag')
            $enrollFlag = [int](Get-ADHDProp $t 'msPKI-Enrollment-Flag')
            $ekus = ConvertTo-ADHDStringArray (Get-ADHDProp $t 'pKIExtendedKeyUsage')
            $appPol = ConvertTo-ADHDStringArray (Get-ADHDProp $t 'msPKI-Certificate-Application-Policy')
            $effective = $ekus
            if ($appPol.Count -gt 0) { $effective = $appPol }
            $sdInfo = Convert-ADHDSecurityDescriptor (Get-ADHDProp $t 'nTSecurityDescriptor')
            [ordered]@{
                name                           = [string]$t.Name
                displayName                    = (Get-ADHDProp $t 'displayName')
                distinguishedName              = [string]$t.DistinguishedName
                schemaVersion                  = (Get-ADHDProp $t 'msPKI-Template-Schema-Version')
                revision                       = (Get-ADHDProp $t 'revision')
                published                      = $script:ADHDPublishedTemplates.Contains([string]$t.Name)
                certificateNameFlag            = $nameFlag
                enrollmentFlag                 = $enrollFlag
                privateKeyFlag                 = (Get-ADHDProp $t 'msPKI-Private-Key-Flag')
                enrolleeSuppliesSubject        = (($nameFlag -band 0x1) -ne 0)
                enrolleeSuppliesSubjectAltName = (($nameFlag -band 0x10000) -ne 0)
                managerApproval                = (($enrollFlag -band 0x2) -ne 0)
                noSecurityExtension            = (($enrollFlag -band 0x80000) -ne 0)
                authorizedSignaturesRequired   = [int](Get-ADHDProp $t 'msPKI-RA-Signature')
                extendedKeyUsage               = $ekus
                applicationPolicies            = $appPol
                clientAuthCapable              = ($effective.Count -eq 0 -or (@($effective | Where-Object { $authEkus -contains $_ }).Count -gt 0))
                enrollmentAgent                = ($effective.Count -eq 0 -or ($effective -contains '1.3.6.1.4.1.311.20.2.1') -or ($effective -contains '2.5.29.37.0'))
                whenChanged                    = (Get-ADHDProp $t 'whenChanged')
                owner                          = $(if ($sdInfo) { $sdInfo.owner } else { $null })
                daclProtected                  = $(if ($sdInfo) { $sdInfo.daclProtected } else { $null })
                aces                           = (Get-ADHDAces $sdInfo)
            }
        }
    }
    $script:ADHDPublishedTemplates = $null
}

# ===========================================================================
# 模組：EntraConnect（在 Entra Connect 伺服器上執行）
# ===========================================================================
function Register-ADHDAccountName {
    # 在 Entra Connect 伺服器等「沒有 AD 使用者清單」的執行環境中，登錄看到的使用者帳號名稱，
    # 讓它們也被假名化；同一把金鑰下產生的假名與 AD bundle 一致（HMAC 為確定性）。
    param([string] $Name, [string] $Sid)
    if ([string]::IsNullOrEmpty($Name) -or -not $script:Ctx.Pseudo) { return }
    if ($Sid -and (Test-ADHDBuiltinSid $Sid)) { return }
    if ($Name -match '^(?i)(NT AUTHORITY|NT SERVICE|BUILTIN|IIS APPPOOL|NT VIRTUAL MACHINE|Window Manager|Font Driver Host)\\') { return }
    $sam = $Name.Trim()
    $bs = $sam.LastIndexOf('\')
    if ($bs -ge 0) { $sam = $sam.Substring($bs + 1) }
    if ($sam.Length -lt 2 -or $sam.EndsWith('$')) { return }   # 電腦 / gMSA 帳號保留（主機名稱不假名化）
    if (Test-ADHDInfraAccount $sam) { return }
    if ($sam.Contains('@') -and (Test-ADHDInfraAccount $sam.Substring(0, $sam.IndexOf('@')))) { return }
    Register-ADHDPii @($sam)
}

function Get-ADHDLocalGroupMembers {
    param([string] $Sid, [string] $Name)
    $list = New-Object System.Collections.Generic.List[object]
    $args2 = @{ ErrorAction = 'Stop' }
    if ($Sid) { $args2.SID = $Sid } else { $args2.Name = $Name }
    foreach ($m in (Get-LocalGroupMember @args2)) {
        if ([string]$m.ObjectClass -eq 'User') { Register-ADHDAccountName -Name ([string]$m.Name) -Sid ([string]$m.SID) }
        $list.Add([ordered]@{
            name            = [string]$m.Name
            sid             = [string]$m.SID
            objectClass     = [string]$m.ObjectClass
            principalSource = [string]$m.PrincipalSource
        })
    }
    return , $list.ToArray()
}

function Invoke-ADHDModuleEntraConnect {
    if (-not (Test-ADHDModule 'ADSync')) {
        foreach ($n in 'entraconnect_server', 'entraconnect_scheduler', 'entraconnect_features', 'entraconnect_connectors', 'entraconnect_config') {
            Add-ADHDSkipped $n 'EntraConnect' '找不到 ADSync 模組；請在 Entra Connect 伺服器上以 Windows PowerShell 5.1（系統管理員）執行'
        }
        return
    }
    Import-ADHDModule 'ADSync'

    Export-ADHDDataset -Name 'entraconnect_server' -Module 'EntraConnect' -Collector {
        $versions = New-Object System.Collections.Generic.List[object]
        foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
            foreach ($i in (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | Where-Object { [string](Get-ADHDProp $_ 'DisplayName') -match 'Azure AD Connect|Entra Connect|Azure AD Connect Health|Microsoft Azure AD Connect' })) {
                $versions.Add([ordered]@{ product = [string]$i.DisplayName; version = [string](Get-ADHDProp $i 'DisplayVersion') })
            }
        }
        $svc = $null
        try { $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='ADSync'" -ErrorAction Stop } catch { }
        if ($svc) { Register-ADHDAccountName -Name ([string]$svc.StartName) }
        $admins = $null; $adsyncAdmins = $null; $err = New-Object System.Collections.Generic.List[string]
        try { $admins = Get-ADHDLocalGroupMembers -Sid 'S-1-5-32-544' } catch { $err.Add('Administrators: ' + $_.Exception.Message) }
        try { $adsyncAdmins = Get-ADHDLocalGroupMembers -Name 'ADSyncAdmins' } catch { $err.Add('ADSyncAdmins: ' + $_.Exception.Message) }
        [ordered]@{
            computerName           = $env:COMPUTERNAME
            products               = $versions
            adsyncServiceAccount   = $(if ($svc) { [string]$svc.StartName } else { $null })
            adsyncServiceState     = $(if ($svc) { [string]$svc.State } else { $null })
            localAdministrators    = $admins
            adsyncAdmins           = $adsyncAdmins
            errors                 = $err
        }
    }

    Export-ADHDDataset -Name 'entraconnect_scheduler' -Module 'EntraConnect' -Collector { Get-ADSyncScheduler }
    Export-ADHDDataset -Name 'entraconnect_features' -Module 'EntraConnect' -Collector { Get-ADSyncAADCompanyFeature }

    Export-ADHDDataset -Name 'entraconnect_connectors' -Module 'EntraConnect' -Collector {
        foreach ($c in (Get-ADSyncConnector)) {
            $params = [ordered]@{}
            foreach ($cp in (Get-ADHDProp $c 'ConnectivityParameters')) {
                if ($null -eq $cp) { continue }
                $n = [string](Get-ADHDProp $cp 'Name')
                if (-not $n -or $n -match '(?i)password|secret|key') { continue }
                $v = [string](Get-ADHDProp $cp 'Value')
                if ($n -match '(?i)login-user|user-?name$') { Register-ADHDAccountName -Name $v }
                $params[$n] = $v
            }
            $parts = New-Object System.Collections.Generic.List[object]
            foreach ($pt in (Get-ADHDProp $c 'Partitions')) {
                if ($null -eq $pt) { continue }
                $scope = Get-ADHDProp $pt 'ConnectorPartitionScope'
                $parts.Add([ordered]@{
                    name     = [string](Get-ADHDProp $pt 'Name')
                    dn       = [string](Get-ADHDProp $pt 'DN')
                    selected = (Get-ADHDProp $pt 'Selected')
                    includes = (ConvertTo-ADHDArray (Get-ADHDProp $scope 'ContainerInclusionList'))
                    excludes = (ConvertTo-ADHDArray (Get-ADHDProp $scope 'ContainerExclusionList'))
                })
            }
            $pwdSync = $null
            if ([string](Get-ADHDProp $c 'Type') -eq 'AD') {
                try { $pwdSync = [bool](Get-ADSyncAADPasswordSyncConfiguration -SourceConnector ([string]$c.Name) -ErrorAction Stop).Enabled } catch { }
            }
            [ordered]@{
                name                   = [string]$c.Name
                identifier             = [string](Get-ADHDProp $c 'Identifier')
                type                   = [string](Get-ADHDProp $c 'Type')
                subtype                = [string](Get-ADHDProp $c 'Subtype')
                version                = (Get-ADHDProp $c 'Version')
                creationTime           = (Get-ADHDProp $c 'CreationTime')
                lastModificationTime   = (Get-ADHDProp $c 'LastModificationTime')
                connectivityParameters = $params
                partitions             = $parts
                objectInclusionList    = (ConvertTo-ADHDArray (Get-ADHDProp $c 'ObjectInclusionList'))
                passwordHashSyncEnabled = $pwdSync
            }
        }
    }

    $rel = 'entraconnect_config'
    $dir = Join-Path $script:Ctx.OutDir $rel
    try {
        if (Get-Command Get-ADSyncServerConfiguration -ErrorAction SilentlyContinue) {
            Get-ADSyncServerConfiguration -Path $dir -ErrorAction Stop | Out-Null
            if ($script:Ctx.Pseudo) {
                foreach ($f in (Get-ChildItem -LiteralPath $dir -Recurse -File | Where-Object { $_.Extension -in @('.xml', '.json', '.txt', '.csv') })) {
                    try {
                        $txt = [System.IO.File]::ReadAllText($f.FullName)
                        $new = Protect-ADHDText $txt
                        if ($new -cne $txt) { [System.IO.File]::WriteAllText($f.FullName, $new, $script:Utf8NoBom) }
                    }
                    catch { Write-ADHDLog ("entraconnect_config 假名化失敗：{0}：{1}" -f $f.Name, $_.Exception.Message) 'WARN' }
                }
            }
            Add-ADHDDirectoryDataset -Name 'entraconnect_config' -Module 'EntraConnect' -RelativeDir $rel
        }
        else { Add-ADHDSkipped 'entraconnect_config' 'EntraConnect' 'Get-ADSyncServerConfiguration 不存在（Entra Connect 版本過舊）' }
    }
    catch {
        Add-ADHDDirectoryDataset -Name 'entraconnect_config' -Module 'EntraConnect' -RelativeDir $rel -Status 'error' -Message (Protect-ADHDText $_.Exception.Message)
    }
}

# ===========================================================================
# 模組：Entra（Microsoft Graph，delegated、唯讀）
# ===========================================================================
function Connect-ADHDGraph {
    param([string[]] $Scopes)
    if ($script:Ctx.GraphConnected) { return $true }
    if (-not (Test-ADHDModule 'Microsoft.Graph.Authentication')) {
        Write-ADHDLog '找不到 Microsoft.Graph.Authentication 模組（Install-Module Microsoft.Graph.Authentication -Scope CurrentUser）' 'ERROR'
        return $false
    }
    Import-ADHDModule 'Microsoft.Graph.Authentication'
    $invoke = Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue
    if (-not $invoke -or -not $invoke.Parameters.ContainsKey('OutputType')) {
        Write-ADHDLog 'Microsoft.Graph.Authentication 版本過舊，需要 2.x 以上（Invoke-MgGraphRequest -OutputType）' 'ERROR'
        return $false
    }
    $cmd = Get-Command Connect-MgGraph
    $mg = @{ Scopes = $Scopes; ErrorAction = 'Stop' }
    if ($cmd.Parameters.ContainsKey('ContextScope')) { $mg.ContextScope = 'Process' }
    if ($cmd.Parameters.ContainsKey('NoWelcome')) { $mg.NoWelcome = $true }
    if ($script:Opt.TenantId) { $mg.TenantId = $script:Opt.TenantId }
    if ($script:Opt.GraphClientId) { $mg.ClientId = $script:Opt.GraphClientId }
    if ($script:Opt.UseDeviceCode) {
        if ($cmd.Parameters.ContainsKey('UseDeviceCode')) { $mg.UseDeviceCode = $true } else { $mg.UseDeviceAuthentication = $true }
    }
    try { Connect-MgGraph @mg | Out-Null }
    catch {
        Write-ADHDLog ('Graph 登入失敗：' + $_.Exception.Message) 'ERROR'
        return $false
    }
    $c = Get-MgContext
    $script:Ctx.Entra.TenantId = [string]$c.TenantId
    $script:Ctx.Entra.Account = [string]$c.Account
    $script:Ctx.Entra.Scopes = @($c.Scopes)
    $missing = @($Scopes | Where-Object { @($c.Scopes) -notcontains $_ })
    if ($missing.Count -gt 0) { Write-ADHDLog ('Graph 權杖缺少下列 scope，相關資料集可能失敗：' + ($missing -join ', ')) 'WARN' }
    $script:Ctx.GraphConnected = $true
    Write-ADHDLog ("Graph 已連線：tenant {0}" -f $script:Ctx.Entra.TenantId)
    return $true
}

function Invoke-ADHDGraphCollection {
    param([Parameter(Mandatory = $true)] [string] $Uri, [int] $Max = 0)
    $next = $Uri
    $n = 0
    while ($next) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject -ErrorAction Stop
        if ($null -eq $resp) { break }
        $valueProp = $resp.PSObject.Properties['value']
        if ($null -ne $valueProp -and ($valueProp.Value -is [System.Collections.IEnumerable]) -and ($valueProp.Value -isnot [string])) {
            foreach ($item in $valueProp.Value) {
                if ($null -eq $item) { continue }
                $item
                $n++
                if ($Max -gt 0 -and $n -ge $Max) { return }
            }
            $nl = $resp.PSObject.Properties['@odata.nextLink']
            $next = $(if ($nl -and $nl.Value) { [string]$nl.Value } else { $null })
        }
        else {
            $resp
            $next = $null
        }
    }
}

function Get-ADHDGraphRefs {
    param([string] $Uri)
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($o in @(Invoke-ADHDGraphCollection -Uri $Uri)) {
        $tp = $o.PSObject.Properties['@odata.type']
        $list.Add([ordered]@{
            id   = [string]$o.id
            type = $(if ($tp) { ([string]$tp.Value) -replace '^#microsoft\.graph\.', '' } else { $null })
        })
    }
    return , $list.ToArray()
}

function Export-ADHDGraphDataset {
    param(
        [string] $Name,
        [string] $Uri,
        [string[]] $PreserveKeys = @(),
        [scriptblock] $OnItem,
        [int] $Max = 0,
        [string] $Module = 'Entra'
    )
    $gUri = $Uri; $gMax = $Max; $gOnItem = $OnItem
    Export-ADHDDataset -Name $Name -Module $Module -PreserveKeys $PreserveKeys -Collector {
        Invoke-ADHDGraphCollection -Uri $gUri -Max $gMax | ForEach-Object {
            if ($gOnItem) { & $gOnItem $_ }
            $_
        }
    }
}

function Test-ADHDMicrosoftOwned {
    param([string] $OwnerTenant)
    return ($script:MicrosoftTenantIds -contains $OwnerTenant)
}

function Invoke-ADHDModuleEntra {
    $e = $script:Ctx.Entra

    Export-ADHDGraphDataset -Name 'entra_organization' -PreserveKeys @('displayName') `
        -Uri 'v1.0/organization?$select=id,displayName,tenantType,createdDateTime,verifiedDomains,onPremisesSyncEnabled,onPremisesLastSyncDateTime'

    Export-ADHDGraphDataset -Name 'entra_domains' `
        -Uri 'v1.0/domains?$select=id,authenticationType,isDefault,isInitial,isVerified,isRoot,supportedServices,passwordValidityPeriodInDays'

    # Users：先探測 signInActivity（需要 P1 + AuditLog.Read.All），不支援就退回
    $userSelect = 'id,userPrincipalName,displayName,givenName,surname,mail,otherMails,accountEnabled,userType,creationType,externalUserState,' +
        'createdDateTime,lastPasswordChangeDateTime,passwordPolicies,onPremisesSyncEnabled,onPremisesSecurityIdentifier,' +
        'onPremisesSamAccountName,onPremisesDistinguishedName,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesDomainName'
    $useSia = $true
    try { [void](Invoke-MgGraphRequest -Method GET -Uri 'v1.0/users?$top=999&$select=id,signInActivity' -OutputType PSObject -ErrorAction Stop) }
    catch { $useSia = $false; Write-ADHDLog ('無法讀取 signInActivity（通常為授權或權限不足），users 將不含最後登入時間：' + $_.Exception.Message) 'WARN' }
    $userUri = 'v1.0/users?$top=999&$select=' + $userSelect + $(if ($useSia) { ',signInActivity' } else { '' })
    Export-ADHDGraphDataset -Name 'entra_users' -Uri $userUri -OnItem {
        param($u)
        $upn = [string]$u.userPrincipalName
        $local = $(if ($upn.Contains('@')) { $upn.Substring(0, $upn.IndexOf('@')) } else { $upn })
        if ((Test-ADHDInfraAccount $local) -or (Test-ADHDInfraAccount ([string]$u.onPremisesSamAccountName))) { return }
        Register-ADHDPii @($upn, $u.displayName, $u.mail, $u.givenName, $u.surname, $u.onPremisesSamAccountName,
            (Get-ADHDDnCn ([string]$u.onPremisesDistinguishedName)), $u.otherMails)
    }

    Export-ADHDGraphDataset -Name 'entra_groups' -PreserveKeys @('displayName', 'onPremisesSamAccountName') `
        -Uri ('v1.0/groups?$top=999&$select=id,displayName,mail,mailEnabled,securityEnabled,groupTypes,isAssignableToRole,' +
              'onPremisesSyncEnabled,onPremisesSecurityIdentifier,onPremisesSamAccountName,membershipRule,membershipRuleProcessingState,createdDateTime,visibility') `
        -OnItem { param($g) $e.GroupIds[[string]$g.id] = [bool]$g.isAssignableToRole }

    Export-ADHDGraphDataset -Name 'entra_role_definitions' -PreserveKeys @('displayName') `
        -Uri 'v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn,isEnabled,templateId,rolePermissions'

    $trackPrincipal = { param($a) if ($a.principalId) { [void]$e.PrincipalIds.Add([string]$a.principalId) } }
    Export-ADHDGraphDataset -Name 'entra_role_assignments' -Uri 'v1.0/roleManagement/directory/roleAssignments' -OnItem $trackPrincipal
    Export-ADHDGraphDataset -Name 'entra_pim_eligibility' -Uri 'v1.0/roleManagement/directory/roleEligibilitySchedules' -OnItem $trackPrincipal
    Export-ADHDGraphDataset -Name 'entra_pim_assignments' -Uri 'v1.0/roleManagement/directory/roleAssignmentSchedules' -OnItem $trackPrincipal

    Export-ADHDGraphDataset -Name 'entra_admin_units' -PreserveKeys @('displayName') `
        -Uri 'v1.0/directory/administrativeUnits?$select=id,displayName,membershipType,membershipRule,visibility' `
        -OnItem { param($u) $e.AdminUnits.Add([string]$u.id) }
    Export-ADHDDataset -Name 'entra_admin_unit_roles' -Module 'Entra' -Collector {
        foreach ($auId in $e.AdminUnits) {
            foreach ($m in @(Invoke-ADHDGraphCollection -Uri ('v1.0/directory/administrativeUnits/{0}/scopedRoleMembers' -f $auId))) {
                if ($m.roleMemberInfo -and $m.roleMemberInfo.id) { [void]$e.PrincipalIds.Add([string]$m.roleMemberInfo.id) }
                $m
            }
        }
    }

    Export-ADHDGraphDataset -Name 'entra_ca_policies' -PreserveKeys @('displayName') -Uri 'v1.0/identity/conditionalAccess/policies' -OnItem {
        param($pol)
        $users = $null
        if ($pol.conditions) { $users = $pol.conditions.users }
        if ($users) {
            foreach ($gid in @($users.includeGroups) + @($users.excludeGroups)) { if ($gid) { [void]$e.ReferencedGroups.Add([string]$gid) } }
        }
    }
    Export-ADHDGraphDataset -Name 'entra_named_locations' -PreserveKeys @('displayName') -Uri 'v1.0/identity/conditionalAccess/namedLocations'
    Export-ADHDGraphDataset -Name 'entra_authorization_policy' -PreserveKeys @('displayName') -Uri 'v1.0/policies/authorizationPolicy'
    Export-ADHDGraphDataset -Name 'entra_security_defaults' -PreserveKeys @('displayName') -Uri 'v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
    Export-ADHDGraphDataset -Name 'entra_auth_methods_policy' -PreserveKeys @('displayName') -Uri 'v1.0/policies/authenticationMethodsPolicy'
    Export-ADHDGraphDataset -Name 'entra_user_registration' -Uri 'v1.0/reports/authenticationMethods/userRegistrationDetails'

    Export-ADHDGraphDataset -Name 'entra_devices' -PreserveKeys @('displayName') `
        -Uri ('v1.0/devices?$top=999&$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,' +
              'isManaged,accountEnabled,approximateLastSignInDateTime,registrationDateTime,onPremisesSyncEnabled,profileType')

    Export-ADHDDataset -Name 'entra_group_memberships' -Module 'Entra' -Collector {
        $targets = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($kv in $e.GroupIds.GetEnumerator()) {
            if ($script:Opt.AllGroupMembers -or $kv.Value -or $e.PrincipalIds.Contains($kv.Key) -or $e.ReferencedGroups.Contains($kv.Key)) {
                [void]$targets.Add($kv.Key)
            }
        }
        Write-ADHDLog ("收集 {0} 個 Entra 群組的成員" -f $targets.Count)
        foreach ($gid in $targets) {
            $members = $null; $owners = $null; $err = $null
            try {
                $members = Get-ADHDGraphRefs ('v1.0/groups/{0}/transitiveMembers?$select=id&$top=999' -f $gid)
                $owners = Get-ADHDGraphRefs ('v1.0/groups/{0}/owners?$select=id' -f $gid)
            }
            catch { $err = $_.Exception.Message }
            [ordered]@{
                groupId            = $gid
                isAssignableToRole = $e.GroupIds[$gid]
                hasRoleAssignment  = $e.PrincipalIds.Contains($gid)
                referencedByCA     = $e.ReferencedGroups.Contains($gid)
                transitiveMembers  = $members
                owners             = $owners
                error              = $err
            }
        }
    }

    Export-ADHDGraphDataset -Name 'entra_applications' -PreserveKeys @('displayName') `
        -Uri ('v1.0/applications?$top=999&$select=id,appId,displayName,signInAudience,createdDateTime,publisherDomain,' +
              'requiredResourceAccess,passwordCredentials,keyCredentials,web,spa,publicClient,isFallbackPublicClient') `
        -OnItem { param($a) $e.Applications.Add([ordered]@{ id = [string]$a.id; appId = [string]$a.appId }) }
    Export-ADHDDataset -Name 'entra_application_owners' -Module 'Entra' -Collector {
        foreach ($a in $e.Applications) {
            $owners = $null; $err = $null
            try { $owners = Get-ADHDGraphRefs ('v1.0/applications/{0}/owners?$select=id' -f $a.id) } catch { $err = $_.Exception.Message }
            [ordered]@{ applicationId = $a.id; appId = $a.appId; owners = $owners; error = $err }
        }
    }

    Export-ADHDGraphDataset -Name 'entra_service_principals' -PreserveKeys @('displayName', 'publisherName') `
        -Uri ('v1.0/servicePrincipals?$top=999&$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,' +
              'appRoleAssignmentRequired,passwordCredentials,keyCredentials,tags,publisherName,verifiedPublisher,signInAudience,preferredSingleSignOnMode') `
        -OnItem { param($s) $e.ServicePrincipals.Add([ordered]@{ id = [string]$s.id; appId = [string]$s.appId; owner = [string]$s.appOwnerOrganizationId; type = [string]$s.servicePrincipalType }) }

    Export-ADHDDataset -Name 'entra_sp_owners' -Module 'Entra' -Collector {
        foreach ($s in $e.ServicePrincipals) {
            if (Test-ADHDMicrosoftOwned $s.owner) { continue }
            $owners = $null; $err = $null
            try { $owners = Get-ADHDGraphRefs ('v1.0/servicePrincipals/{0}/owners?$select=id' -f $s.id) } catch { $err = $_.Exception.Message }
            [ordered]@{ servicePrincipalId = $s.id; appId = $s.appId; owners = $owners; error = $err }
        }
    }

    Export-ADHDDataset -Name 'entra_app_role_assignments' -Module 'Entra' -PreserveKeys @('principalDisplayName', 'resourceDisplayName') -Collector {
        foreach ($s in $e.ServicePrincipals) {
            if ((Test-ADHDMicrosoftOwned $s.owner) -and $s.type -ne 'ManagedIdentity') { continue }
            foreach ($a in @(Invoke-ADHDGraphCollection -Uri ('v1.0/servicePrincipals/{0}/appRoleAssignments' -f $s.id))) {
                if ($a.resourceId) { [void]$e.ResourceIds.Add([string]$a.resourceId) }
                $a
            }
        }
    }

    Export-ADHDGraphDataset -Name 'entra_oauth2_grants' -Uri 'v1.0/oauth2PermissionGrants' -OnItem {
        param($g) if ($g.resourceId) { [void]$e.ResourceIds.Add([string]$g.resourceId) }
    }

    Export-ADHDDataset -Name 'entra_permission_catalog' -Module 'Entra' -PreserveKeys @('displayName') -Collector {
        foreach ($rid in $e.ResourceIds) {
            $r = @(Invoke-ADHDGraphCollection -Uri ('v1.0/servicePrincipals/{0}?$select=id,appId,displayName,appRoles,oauth2PermissionScopes' -f $rid)) | Select-Object -First 1
            if ($null -eq $r) { continue }
            [ordered]@{
                id          = [string]$r.id
                appId       = [string]$r.appId
                displayName = [string]$r.displayName
                appRoles    = @(@($r.appRoles) | Where-Object { $_ } | ForEach-Object { [ordered]@{ id = [string]$_.id; value = [string]$_.value; allowedMemberTypes = (ConvertTo-ADHDArray $_.allowedMemberTypes); isEnabled = $_.isEnabled } })
                scopes      = @(@($r.oauth2PermissionScopes) | Where-Object { $_ } | ForEach-Object { [ordered]@{ id = [string]$_.id; value = [string]$_.value; type = [string]$_.type; isEnabled = $_.isEnabled } })
            }
        }
    }

    Export-ADHDGraphDataset -Name 'entra_risky_users' -Uri 'v1.0/identityProtection/riskyUsers'
}

function Invoke-ADHDModuleEntraLogs {
    $since = [DateTime]::UtcNow.AddDays(-$script:Opt.LogDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $max = $script:Opt.MaxLogRecords
    Export-ADHDGraphDataset -Name 'entra_signins' -Module 'EntraLogs' -Max $max `
        -PreserveKeys @('appDisplayName', 'resourceDisplayName') `
        -Uri ('v1.0/auditLogs/signIns?$top=1000&$filter=' + [uri]::EscapeDataString("createdDateTime ge $since"))
    Export-ADHDGraphDataset -Name 'entra_directory_audits' -Module 'EntraLogs' -Max $max `
        -Uri ('v1.0/auditLogs/directoryAudits?$filter=' + [uri]::EscapeDataString("activityDateTime ge $since"))
    Export-ADHDGraphDataset -Name 'entra_risk_detections' -Module 'EntraLogs' -Max $max `
        -Uri ('v1.0/identityProtection/riskDetections?$filter=' + [uri]::EscapeDataString("detectedDateTime ge $since"))
}

# ===========================================================================
# 模組：SecurityAlerts（Defender for Identity / Endpoint 告警，Graph security/alerts_v2，唯讀）
# ===========================================================================
function Protect-ADHDFreeText {
    # 自由文字（例如告警標題「Suspected DCSync attack by jdoe」）：把已登錄的帳號 / 顯示名稱（1-4 個字）換成假名
    param([string] $Text)
    if ([string]::IsNullOrEmpty($Text) -or -not $script:Ctx.Pseudo) { return $Text }
    $t = Protect-ADHDText $Text
    $tokens = @([regex]::Matches($t, '[\p{L}\p{N}_.$\-]+'))
    $hits = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        for ($n = 4; $n -ge 1; $n--) {
            if ($i + $n -gt $tokens.Count) { continue }
            $start = $tokens[$i].Index
            $end = $tokens[$i + $n - 1].Index + $tokens[$i + $n - 1].Length
            $cand = $t.Substring($start, $end - $start)
            if ($script:Ctx.PiiMap.ContainsKey($cand)) { [void]$hits.Add($cand); break }
        }
    }
    foreach ($h in ($hits | Sort-Object Length -Descending)) {
        $t = [regex]::Replace($t, '(?<![\p{L}\p{N}_])' + [regex]::Escape($h) + '(?![\p{L}\p{N}_])', $script:Ctx.PiiMap[$h], 'IgnoreCase')
    }
    return $t
}

function ConvertTo-ADHDAlertRecord {
    # 只保留偵測與關聯需要的欄位：不帶 description / recommendedActions / 顯示名稱等自由文字與個資
    param($Alert)
    $evidence = foreach ($ev in (Get-ADHDProp $Alert 'evidence')) {   # Get-ADHDProp keeps the collection whole: no @()
        if ($null -eq $ev) { continue }
        $ua = Get-ADHDProp $ev 'userAccount'
        $acct = $null
        if ($ua) {
            $name = [string](Get-ADHDProp $ua 'accountName')
            $sid = [string](Get-ADHDProp $ua 'userSid')
            Register-ADHDAccountName -Name $name -Sid $sid
            $acct = [ordered]@{
                accountName       = $name
                domainName        = [string](Get-ADHDProp $ua 'domainName')
                userSid           = $sid
                azureAdUserId     = [string](Get-ADHDProp $ua 'azureAdUserId')
                userPrincipalName = [string](Get-ADHDProp $ua 'userPrincipalName')
            }
        }
        [ordered]@{
            type              = [string](Get-ADHDProp $ev '@odata.type')
            roles             = (ConvertTo-ADHDStringArray (Get-ADHDProp $ev 'roles'))
            verdict           = [string](Get-ADHDProp $ev 'verdict')
            remediationStatus = [string](Get-ADHDProp $ev 'remediationStatus')
            userAccount       = $acct
            deviceDnsName     = [string](Get-ADHDProp $ev 'deviceDnsName')
            mdeDeviceId       = [string](Get-ADHDProp $ev 'mdeDeviceId')
            ipAddress         = [string](Get-ADHDProp $ev 'ipAddress')
        }
    }
    [ordered]@{
        id                    = [string](Get-ADHDProp $Alert 'id')
        incidentId            = [string](Get-ADHDProp $Alert 'incidentId')
        title                 = (Protect-ADHDFreeText ([string](Get-ADHDProp $Alert 'title')))
        severity              = [string](Get-ADHDProp $Alert 'severity')
        status                = [string](Get-ADHDProp $Alert 'status')
        classification        = [string](Get-ADHDProp $Alert 'classification')
        determination         = [string](Get-ADHDProp $Alert 'determination')
        serviceSource         = [string](Get-ADHDProp $Alert 'serviceSource')
        detectionSource       = [string](Get-ADHDProp $Alert 'detectionSource')
        category              = [string](Get-ADHDProp $Alert 'category')
        mitreTechniques       = (ConvertTo-ADHDStringArray (Get-ADHDProp $Alert 'mitreTechniques'))
        createdDateTime       = (Get-ADHDProp $Alert 'createdDateTime')
        firstActivityDateTime = (Get-ADHDProp $Alert 'firstActivityDateTime')
        lastActivityDateTime  = (Get-ADHDProp $Alert 'lastActivityDateTime')
        evidence              = @($evidence)
    }
}

function Invoke-ADHDModuleSecurityAlerts {
    $since = [DateTime]::UtcNow.AddDays(-$script:Opt.LogDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $uri = 'v1.0/security/alerts_v2?$top=500&$filter=' + [uri]::EscapeDataString("createdDateTime ge $since")
    $max = $script:Opt.MaxLogRecords
    Export-ADHDDataset -Name 'security_alerts' -Module 'SecurityAlerts' -PreserveKeys @('category', 'serviceSource', 'detectionSource') -Collector {
        Invoke-ADHDGraphCollection -Uri $uri -Max $max | ForEach-Object { ConvertTo-ADHDAlertRecord $_ }
    }
}

# ===========================================================================
# 模組：DCLogs
# ===========================================================================
function ConvertTo-ADHDEventRecord {
    param($EventRecord, [string] $Dc)
    $xml = [xml]$EventRecord.ToXml()
    $data = [ordered]@{}
    $i = 0
    foreach ($d in @($xml.Event.EventData.Data)) {
        if ($null -eq $d) { continue }
        if ($d -is [string]) { $data[('Data{0}' -f $i)] = $d }
        else {
            $n = [string]$d.GetAttribute('Name')
            if (-not $n) { $n = 'Data{0}' -f $i }
            $data[$n] = $d.InnerText
        }
        $i++
    }
    $kw = [long]$EventRecord.Keywords
    $outcome = $null
    if (($kw -band 0x0020000000000000) -ne 0) { $outcome = 'success' }
    elseif (($kw -band 0x0010000000000000) -ne 0) { $outcome = 'failure' }
    [ordered]@{
        dc          = $Dc
        eventId     = [int]$EventRecord.Id
        recordId    = $EventRecord.RecordId
        timeCreated = $EventRecord.TimeCreated
        machineName = [string]$EventRecord.MachineName
        outcome     = $outcome
        data        = $data
    }
}

function Invoke-ADHDModuleDCLogs {
    $p = $script:Ctx.ADParams
    $dcs = @($script:Opt.DomainControllers)
    if ($dcs.Count -eq 0 -or -not $dcs[0]) {
        try { $dcs = @(Get-ADDomainController -Filter * @p | ForEach-Object { [string]$_.HostName }) }
        catch { Add-ADHDSkipped 'dc_security_events' 'DCLogs' ('無法列出 DC：' + $_.Exception.Message); return }
    }
    $start = (Get-Date).AddDays(-$script:Opt.LogDays)
    Export-ADHDDataset -Name 'dc_security_events' -Module 'DCLogs' -Collector {
        foreach ($dc in $dcs) {
            $consecutiveErrors = 0
            foreach ($id in $script:Opt.EventIds) {
                $ev = @{
                    ComputerName    = $dc
                    FilterHashtable = @{ LogName = 'Security'; Id = $id; StartTime = $start }
                    MaxEvents       = $script:Opt.MaxEventsPerId
                    ErrorAction     = 'Stop'
                }
                if ($script:Opt.Credential) { $ev.Credential = $script:Opt.Credential }
                $events = $null
                try { $events = @(Get-WinEvent @ev); $consecutiveErrors = 0 }
                catch {
                    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or $_.Exception.Message -match 'No events were found') { continue }
                    $consecutiveErrors++
                    Write-ADHDLog ("{0} 事件 {1} 讀取失敗：{2}" -f $dc, $id, $_.Exception.Message) 'WARN'
                    if ($consecutiveErrors -ge 2) { Write-ADHDLog "連續失敗，略過 DC $dc" 'WARN'; break }
                    continue
                }
                foreach ($evt in $events) { ConvertTo-ADHDEventRecord -EventRecord $evt -Dc $dc }
            }
        }
    }
}

# ===========================================================================
# 收尾
# ===========================================================================
function Complete-ADHDBundle {
    $finished = [DateTime]::UtcNow
    $ad = $script:Ctx.AD
    $manifest = [ordered]@{
        schema           = $script:SchemaVersion
        collector        = [ordered]@{ name = 'Collect-ADHD.ps1'; version = $script:CollectorVersion }
        bundle           = $script:Ctx.BundleName
        label            = $script:Ctx.Label
        startedUtc       = $script:Ctx.StartedUtc
        finishedUtc      = $finished
        runContext       = [ordered]@{
            computer   = $env:COMPUTERNAME
            user       = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
            psVersion  = $PSVersionTable.PSVersion.ToString()
            psEdition  = [string]$PSVersionTable.PSEdition
            os         = [Environment]::OSVersion.VersionString
            modules    = $script:Ctx.ModuleVersions
            parameters = [ordered]@{
                include         = $script:Opt.Include
                server          = $script:Opt.Server
                fullAcl         = [bool]$script:Opt.FullAcl
                allGroupMembers = [bool]$script:Opt.AllGroupMembers
                logDays         = $script:Opt.LogDays
                maxLogRecords   = $script:Opt.MaxLogRecords
                eventIds        = $script:Opt.EventIds
                maxEventsPerId  = $script:Opt.MaxEventsPerId
                skipGpoXml      = [bool]$script:Opt.SkipGpoXml
            }
        }
        scope            = [ordered]@{
            adForest      = $(if ($ad) { $ad.ForestName } else { $null })
            adDomain      = $(if ($ad) { $ad.DomainDns } else { $null })
            adDomainSid   = $(if ($ad) { $ad.DomainSid } else { $null })
            adQueriedDc   = $(if ($ad) { [string]$script:Ctx.ADParams.Server } else { $null })
            entraTenantId = $script:Ctx.Entra.TenantId
            graphAccount  = $script:Ctx.Entra.Account
            graphScopes   = $script:Ctx.Entra.Scopes
        }
        pseudonymization = [ordered]@{
            enabled   = [bool]$script:Ctx.Pseudo
            algorithm = 'HMAC-SHA256(lowercase(value)), first 48 bits hex, prefix "u-"; e-mail keeps @domain'
            keyId     = $script:Ctx.KeyId
            registered = $script:Ctx.PiiMap.Count
        }
        datasets         = $script:Ctx.Datasets
        warnings         = $script:Ctx.Warnings
    }

    # manifest 本身不做假名化（只有操作者與統計資訊）
    $pseudoState = $script:Ctx.Pseudo
    $script:Ctx.Pseudo = $false
    $json = ConvertTo-ADHDJson -Value $manifest
    $script:Ctx.Pseudo = $pseudoState
    [System.IO.File]::WriteAllText((Join-Path $script:Ctx.OutDir 'manifest.json'), $json, $script:Utf8NoBom)

    if ($script:Ctx.Pseudo -and -not $script:Opt.NoMappingFile -and $script:Ctx.PiiReverse.Count -gt 0) {
        $mapPath = Join-Path (Split-Path -Parent $script:Ctx.KeyFile) ('ADHD-pseudonym-map-{0}.csv' -f $script:Ctx.BundleName)
        $sw = New-Object System.IO.StreamWriter -ArgumentList $mapPath, $false, (New-Object System.Text.UTF8Encoding -ArgumentList $true)
        try {
            $sw.WriteLine('pseudonym,original')
            foreach ($kv in $script:Ctx.PiiReverse.GetEnumerator()) {
                $sw.WriteLine(('"{0}","{1}"' -f $kv.Key.Replace('"', '""'), $kv.Value.Replace('"', '""')))
            }
        }
        finally { $sw.Dispose() }
        Write-ADHDLog ("假名對照表：{0}（留在子公司，不要帶回 lab）" -f $mapPath) 'WARN'
    }

    $zipPath = $null
    if (-not $script:Opt.NoZip) {
        $zipPath = $script:Ctx.OutDir + '.zip'
        try {
            if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
            try {
                # Windows PowerShell 5.1（.NET Framework）的 ZipFile 可能以 '\' 作為路徑分隔；lab 端 verify_bundle.py / unzip 皆可處理
                Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
                Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
                [System.IO.Compression.ZipFile]::CreateFromDirectory($script:Ctx.OutDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $true)
            }
            catch {
                Write-ADHDLog ('ZipFile 不可用，改用 Compress-Archive：' + $_.Exception.Message) 'WARN'
                if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
                Compress-Archive -LiteralPath $script:Ctx.OutDir -DestinationPath $zipPath -CompressionLevel Optimal -ErrorAction Stop
            }
            $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
            [System.IO.File]::WriteAllText($zipPath + '.sha256', ('{0}  {1}' -f $zipHash, (Split-Path -Leaf $zipPath)), $script:Utf8NoBom)
            Write-ADHDLog ("Bundle 壓縮檔：{0}" -f $zipPath)
            Write-ADHDLog ("SHA256：{0}" -f $zipHash)
        }
        catch {
            Write-ADHDLog ('壓縮失敗，請直接攜帶資料夾：' + $_.Exception.Message) 'WARN'
            $zipPath = $null
        }
    }

    Write-Host ''
    Write-Host '==== ADHD 收集結果 ====' -ForegroundColor Cyan
    $script:Ctx.Datasets | ForEach-Object {
        [pscustomobject]@{ Dataset = $_.name; Module = $_.module; Status = $_.status; Records = $_.records }
    } | Format-Table -AutoSize | Out-Host
    Write-Host ("Bundle 資料夾：{0}" -f $script:Ctx.OutDir)
    if ($zipPath) { Write-Host ("Bundle 壓縮檔：{0}" -f $zipPath) }
    if ($script:Ctx.Pseudo) { Write-Host ("假名化金鑰（勿帶走）：{0}" -f $script:Ctx.KeyFile) -ForegroundColor Yellow }

    return [pscustomobject]@{
        BundlePath = $script:Ctx.OutDir
        ZipPath    = $zipPath
        Datasets   = $script:Ctx.Datasets.Count
        Errors     = @($script:Ctx.Datasets | Where-Object { $_.status -in @('error', 'partial') }).Count
    }
}

# ===========================================================================
# 主流程
# ===========================================================================
function Invoke-ADHDMain {
    if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
        throw "目前 PowerShell 為 $($ExecutionContext.SessionState.LanguageMode)，本腳本需要 FullLanguage 模式。"
    }
    $script:Opt = @{
        Include           = @($Include)
        Server            = $Server
        Credential        = $Credential
        TenantId          = $TenantId
        GraphClientId     = $GraphClientId
        UseDeviceCode     = [bool]$UseDeviceCode
        FullAcl           = [bool]$FullAcl
        AllGroupMembers   = [bool]$AllGroupMembers
        LogDays           = $LogDays
        MaxLogRecords     = $MaxLogRecords
        DomainControllers = @($DomainControllers | Where-Object { $_ })
        EventIds          = @($EventIds)
        MaxEventsPerId    = $MaxEventsPerId
        SkipGpoXml        = [bool]$SkipGpoXml
        NoZip             = [bool]$NoZip
        NoMappingFile     = [bool]$NoMappingFile
    }
    $oldProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        Initialize-ADHDContext -OutputRoot $OutputRoot -Label $Label
        Initialize-ADHDPseudonymizer -KeyFile $PseudonymKeyFile -Disabled:$NoPseudonymize
        Write-ADHDLog ("ADHD Collector {0}：模組 {1}" -f $script:CollectorVersion, ($script:Opt.Include -join ', '))

        $inc = $script:Opt.Include
        $adModules = @('AD', 'ADACL', 'GPO', 'ADCS', 'DCLogs', 'SecurityAlerts') | Where-Object { $inc -contains $_ }
        $adOk = $false
        if ($adModules) {
            $adOk = Initialize-ADHDAdContext
            if ($adOk -and $inc -notcontains 'AD') { Register-ADHDAdUserPii }
        }

        foreach ($m in @('AD', 'ADACL', 'GPO', 'ADCS', 'EntraConnect', 'Entra', 'EntraLogs', 'SecurityAlerts', 'DCLogs')) {
            if ($inc -notcontains $m) { continue }
            Write-ADHDLog "==== 模組 $m ===="
            try {
                switch ($m) {
                    'AD'           { if ($adOk) { Invoke-ADHDModuleAD } else { Add-ADHDSkipped 'AD' 'AD' ('AD 環境初始化失敗：' + $script:Ctx.ADInitError) } }
                    'ADACL'        { if ($adOk) { Invoke-ADHDModuleADACL } else { Add-ADHDSkipped 'ADACL' 'ADACL' ('AD 環境初始化失敗：' + $script:Ctx.ADInitError) } }
                    'GPO'          { if ($adOk) { Invoke-ADHDModuleGPO } else { Add-ADHDSkipped 'GPO' 'GPO' ('AD 環境初始化失敗：' + $script:Ctx.ADInitError) } }
                    'ADCS'         { if ($adOk) { Invoke-ADHDModuleADCS } else { Add-ADHDSkipped 'ADCS' 'ADCS' ('AD 環境初始化失敗：' + $script:Ctx.ADInitError) } }
                    'EntraConnect' { Invoke-ADHDModuleEntraConnect }
                    'Entra' {
                        $scopes = @('Directory.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'AuditLog.Read.All',
                            'Application.Read.All', 'UserAuthenticationMethod.Read.All', 'IdentityRiskyUser.Read.All')
                        if ($inc -contains 'EntraLogs') { $scopes += 'IdentityRiskEvent.Read.All' }
                        if ($inc -contains 'SecurityAlerts') { $scopes += 'SecurityAlert.Read.All' }   # 一次登入取得所有需要的權限
                        if (Connect-ADHDGraph -Scopes $scopes) { Invoke-ADHDModuleEntra } else { Add-ADHDSkipped 'Entra' 'Entra' 'Graph 連線失敗' }
                    }
                    'EntraLogs' {
                        $scopes = @('AuditLog.Read.All', 'Directory.Read.All', 'IdentityRiskEvent.Read.All')
                        if ($inc -contains 'SecurityAlerts') { $scopes += 'SecurityAlert.Read.All' }
                        if (Connect-ADHDGraph -Scopes $scopes) { if ($inc -notcontains 'Entra') { Register-ADHDEntraUserPii }; Invoke-ADHDModuleEntraLogs } else { Add-ADHDSkipped 'EntraLogs' 'EntraLogs' 'Graph 連線失敗' }
                    }
                    'SecurityAlerts' {
                        if (Connect-ADHDGraph -Scopes @('SecurityAlert.Read.All', 'Directory.Read.All')) { if ($inc -notcontains 'Entra') { Register-ADHDEntraUserPii }; Invoke-ADHDModuleSecurityAlerts } else { Add-ADHDSkipped 'SecurityAlerts' 'SecurityAlerts' 'Graph 連線失敗' }
                    }
                    'DCLogs'       { if ($adOk -or $script:Opt.DomainControllers.Count -gt 0) { Invoke-ADHDModuleDCLogs } else { Add-ADHDSkipped 'DCLogs' 'DCLogs' ('AD 環境初始化失敗且未指定 -DomainControllers：' + $script:Ctx.ADInitError) } }
                }
            }
            catch {
                Write-ADHDLog ("模組 {0} 未預期錯誤：{1}" -f $m, $_.Exception.Message) 'ERROR'
                Add-ADHDSkipped $m $m ('未預期錯誤：' + (Protect-ADHDText $_.Exception.Message))
            }
        }

        if ($script:Ctx.GraphConnected -and -not $script:ADHDTestHooks) {
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
        }
        return (Complete-ADHDBundle)
    }
    finally {
        $ProgressPreference = $oldProgress
    }
}

# 以 dot-source 載入（例如測試）時不執行主流程
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-ADHDMain
}
