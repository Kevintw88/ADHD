<#
.SYNOPSIS
    Collect-ADHD.ps1 的端對端煙霧測試：以 mock 取代 AD / GroupPolicy / ADSync / Graph / Get-WinEvent，
    執行所有模組並驗證輸出格式、假名化與禁止欄位過濾。可在 Linux / macOS 的 pwsh 7 上執行。

.EXAMPLE
    pwsh -NoProfile -File tests/powershell/Invoke-CollectorSmokeTest.ps1
#>
[CmdletBinding()]
param(
    [string] $OutputRoot = (Join-Path ([System.IO.Path]::GetTempPath()) ('adhd-smoke-' + [guid]::NewGuid().ToString('N')))
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$collector = Join-Path $repoRoot 'collectors/powershell/Collect-ADHD.ps1'
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

# 載入收集器函式（dot-source 不會執行主流程）
. $collector -Include AD, ADACL, GPO, ADCS, EntraConnect, Entra, EntraLogs, DCLogs -OutputRoot $OutputRoot -Label 'SmokeSub' -TenantId 'tid-123'

$script:ADHDTestHooks = @{
    AvailableModules = @('ActiveDirectory', 'GroupPolicy', 'ADSync', 'Microsoft.Graph.Authentication')
}

# ---------------------------------------------------------------------------
# 測試資料
# ---------------------------------------------------------------------------
$DomainDN = 'DC=sub,DC=local'
$ConfigNC = "CN=Configuration,$DomainDN"
$SchemaNC = "CN=Schema,$ConfigNC"
$Pks = "CN=Public Key Services,CN=Services,$ConfigNC"
$DcsyncGuid = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
$EnrollGuid = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'

function New-MockAce {
    param([string] $Sid, [string] $Rights = 'GenericAll', [guid] $ObjectType = [guid]::Empty)
    [pscustomobject]@{
        IdentityReference     = [pscustomobject]@{ Value = $Sid }
        AccessControlType     = 'Allow'
        ActiveDirectoryRights = $Rights
        ObjectType            = $ObjectType
        InheritedObjectType   = [guid]::Empty
        InheritanceType       = 'None'
    }
}
function New-MockSd {
    param([object[]] $Aces, [string] $Owner = 'S-1-5-21-1-2-3-512')
    $sd = [pscustomobject]@{ AreAccessRulesProtected = $false; MockAces = $Aces; MockOwner = $Owner }
    $sd | Add-Member -MemberType ScriptMethod -Name GetAccessRules -Value { param($a, $b, $t) , @($this.MockAces) }
    $sd | Add-Member -MemberType ScriptMethod -Name GetOwner -Value { param($t) [pscustomobject]@{ Value = $this.MockOwner } }
    $sd
}
$RootSd = New-MockSd @(
    (New-MockAce 'S-1-5-21-1-2-3-1106' 'ExtendedRight' $DcsyncGuid),
    (New-MockAce 'S-1-5-21-1-2-3-512' 'GenericAll')
)
$UserJdoeDn = 'CN=John Doe,OU=Staff,DC=sub,DC=local'

function New-MockUser {
    param([string] $Sam, [string] $Name, [string] $Rid, [hashtable] $Extra = @{})
    $o = [ordered]@{
        SamAccountName = $Sam; Name = $Name; SID = "S-1-5-21-1-2-3-$Rid"; ObjectGUID = [guid]::NewGuid()
        DistinguishedName = "CN=$Name,CN=Users,$DomainDN"; Enabled = $true; UserPrincipalName = "$Sam@sub.local"
        GivenName = $null; Surname = $null; userAccountControl = 0x200; pwdLastSet = 133700000000000000
        lastLogonTimestamp = 133710000000000000; accountExpires = 9223372036854775807; whenCreated = [datetime]'2024-01-01'
        whenChanged = [datetime]'2026-01-01'; primaryGroupID = 513; servicePrincipalName = @(); sIDHistory = @()
        'msDS-KeyCredentialLink' = @(); 'msDS-AllowedToDelegateTo' = @()
    }
    foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] }
    [pscustomobject]$o
}

# ---------------------------------------------------------------------------
# Mock：ActiveDirectory
# ---------------------------------------------------------------------------
function Get-ADDomain {
    [CmdletBinding()] param($Server, $Credential)
    [pscustomobject]@{
        DistinguishedName = $DomainDN; DNSRoot = 'sub.local'; NetBIOSName = 'SUB'; DomainSID = 'S-1-5-21-1-2-3'
        PDCEmulator = 'dc01.sub.local'; DomainMode = 'Windows2016Domain'; RIDMaster = 'dc01.sub.local'
        InfrastructureMaster = 'dc01.sub.local'; ParentDomain = $null; ChildDomains = @()
    }
}
function Get-ADRootDSE { [CmdletBinding()] param($Server, $Credential) [pscustomobject]@{ configurationNamingContext = $ConfigNC; schemaNamingContext = $SchemaNC } }
function Get-ADForest {
    [CmdletBinding()] param($Server, $Credential)
    [pscustomobject]@{
        Name = 'sub.local'; RootDomain = 'sub.local'; ForestMode = 'Windows2016Forest'; Domains = @('sub.local')
        GlobalCatalogs = @('dc01.sub.local'); Sites = @('Taipei'); UPNSuffixes = @('sub.com'); SPNSuffixes = @()
        SchemaMaster = 'dc01.sub.local'; DomainNamingMaster = 'dc01.sub.local'
    }
}
function Get-ADOptionalFeature { [CmdletBinding()] param($Filter, $Server, $Credential) [pscustomobject]@{ Name = 'Recycle Bin Feature'; EnabledScopes = @('x') } }
function Get-ADDefaultDomainPasswordPolicy {
    [CmdletBinding()] param($Server, $Credential)
    [pscustomobject]@{
        ComplexityEnabled = $true; MinPasswordLength = 8; PasswordHistoryCount = 24; MaxPasswordAge = [timespan]::FromDays(90)
        MinPasswordAge = [timespan]::FromDays(1); LockoutThreshold = 0; LockoutDuration = [timespan]::FromMinutes(30)
        LockoutObservationWindow = [timespan]::FromMinutes(30); ReversibleEncryptionEnabled = $false
    }
}
function Get-ADFineGrainedPasswordPolicy { [CmdletBinding()] param($Filter, $Server, $Credential) throw 'Access is denied' }
function Get-ADTrust {
    [CmdletBinding()] param($Filter, $Server, $Credential)
    [pscustomobject]@{
        Name = 'hq.local'; Target = 'hq.local'; Source = $DomainDN; DistinguishedName = "CN=hq.local,CN=System,$DomainDN"
        Direction = 'Bidirectional'; TrustType = 'Uplevel'; TrustAttributes = 8; ForestTransitive = $true; IntraForest = $false
        SelectiveAuthentication = $false; SIDFilteringQuarantined = $false; SIDFilteringForestAware = $false; TGTDelegation = $false
        DisallowTransivity = $false; UsesAESKeys = $true; UsesRC4Encryption = $false
    }
}
function Get-ADDomainController {
    [CmdletBinding()] param($Filter, $Server, $Credential)
    [pscustomobject]@{
        Name = 'DC01'; HostName = 'dc01.sub.local'; IPv4Address = '10.0.0.10'; Site = 'Taipei'; Domain = 'sub.local'
        OperatingSystem = 'Windows Server 2022 Standard'; OperatingSystemVersion = '10.0 (20348)'; IsGlobalCatalog = $true
        IsReadOnly = $false; OperationMasterRoles = @('PDCEmulator', 'RIDMaster'); ComputerObjectDN = "CN=DC01,OU=Domain Controllers,$DomainDN"; Enabled = $true
    }
}
function Get-ADOrganizationalUnit {
    [CmdletBinding()] param($Filter, $Properties, $ResultPageSize, $Server, $Credential)
    [pscustomobject]@{
        Name = 'Staff'; DistinguishedName = "OU=Staff,$DomainDN"; gPLink = '[LDAP://cn={6AC1786C-016F-11D2-945F-00C04FB984F9},cn=policies,cn=system,DC=sub,DC=local;2]'
        gPOptions = 1; description = 'staff accounts'; whenCreated = [datetime]'2024-01-01'; ProtectedFromAccidentalDeletion = $true
    }
}
function Get-ADUser {
    [CmdletBinding()] param($Identity, $Filter, $Properties, $ResultPageSize, $Server, $Credential)
    if ($Identity -eq 'krbtgt') { return [pscustomobject]@{ pwdLastSet = 132000000000000000 } }
    New-MockUser 'Administrator' 'Administrator' '500' @{ adminCount = 1 }
    New-MockUser 'krbtgt' 'krbtgt' '502' @{ Enabled = $false }
    New-MockUser 'jdoe' 'John Doe' '1105' @{
        DistinguishedName = $UserJdoeDn; UserPrincipalName = 'jdoe@sub.local'; GivenName = 'John'; Surname = 'Doe'
        displayName = 'John Doe'; mail = 'john.doe@sub.com'; adminCount = 1; description = 'temp password: Kq#Zx!7w'
        servicePrincipalName = @('MSSQLSvc/sql01.sub.local:1433'); userAccountControl = (0x200 -bor 0x10000 -bor 0x400000)
        department = 'IT'; 'mS-DS-ConsistencyGuid' = ([guid]'11111111-2222-3333-4444-555555555555').ToByteArray()
    }
    New-MockUser 'MSOL_abc123' 'MSOL_abc123' '1106' @{ description = 'Account created by Microsoft Azure Active Directory Connect' }
}
function Get-ADComputer {
    [CmdletBinding()] param($Filter, $Properties, $ResultPageSize, $Server, $Credential)
    [pscustomobject]@{
        Name = 'DC01'; SamAccountName = 'DC01$'; SID = 'S-1-5-21-1-2-3-1000'; ObjectGUID = [guid]::NewGuid()
        DistinguishedName = "CN=DC01,OU=Domain Controllers,$DomainDN"; Enabled = $true; dNSHostName = 'dc01.sub.local'
        operatingSystem = 'Windows Server 2022 Standard'; userAccountControl = 0x82000; primaryGroupID = 516
        servicePrincipalName = @('ldap/dc01.sub.local'); pwdLastSet = 133700000000000000
    }
    [pscustomobject]@{
        Name = 'WS01'; SamAccountName = 'WS01$'; SID = 'S-1-5-21-1-2-3-1201'; ObjectGUID = [guid]::NewGuid()
        DistinguishedName = "CN=WS01,OU=Workstations,$DomainDN"; Enabled = $true; dNSHostName = 'ws01.sub.local'
        operatingSystem = 'Windows 11 Enterprise'; userAccountControl = 0x1000; primaryGroupID = 515
        'msLAPS-PasswordExpirationTime' = 134100000000000000; 'ms-Mcs-AdmPwd' = 'MUST-NOT-LEAK'
    }
}
function Get-ADServiceAccount {
    [CmdletBinding()] param($Filter, $Properties, $Server, $Credential)
    [pscustomobject]@{
        Name = 'gmsa-web'; SamAccountName = 'gmsa-web$'; SID = 'S-1-5-21-1-2-3-1300'; ObjectClass = 'msDS-GroupManagedServiceAccount'
        DistinguishedName = "CN=gmsa-web,CN=Managed Service Accounts,$DomainDN"; Enabled = $true; userAccountControl = 0x1000
        PrincipalsAllowedToRetrieveManagedPassword = @("CN=IT Staff,OU=Groups,$DomainDN")
        'msDS-ManagedPassword' = 'MUST-NOT-LEAK'
    }
}
function Get-ADGroup {
    [CmdletBinding()] param($Filter, $Properties, $ResultPageSize, $Server, $Credential)
    [pscustomobject]@{
        Name = 'Domain Admins'; SamAccountName = 'Domain Admins'; SID = 'S-1-5-21-1-2-3-512'; ObjectGUID = [guid]::NewGuid()
        DistinguishedName = "CN=Domain Admins,CN=Users,$DomainDN"; GroupScope = 'Global'; GroupCategory = 'Security'; adminCount = 1
        member = @($UserJdoeDn, "CN=Administrator,CN=Users,$DomainDN", "CN=S-1-5-21-9-9-9-1000,CN=ForeignSecurityPrincipals,$DomainDN")
    }
    [pscustomobject]@{
        Name = 'IT Staff'; SamAccountName = 'IT Staff'; SID = 'S-1-5-21-1-2-3-1200'; ObjectGUID = [guid]::NewGuid()
        DistinguishedName = "CN=IT Staff,OU=Groups,$DomainDN"; GroupScope = 'Global'; GroupCategory = 'Security'
        member = @("CN=WS01,OU=Workstations,$DomainDN", "CN=Ext Contact,OU=Contacts,$DomainDN"); managedBy = $UserJdoeDn
    }
}
function Get-ADObject {
    [CmdletBinding()]
    param($Identity, $SearchBase, $SearchScope, $LDAPFilter, $Filter, [string[]] $Properties, $ResultPageSize, $Server, $Credential)
    if ($Identity) {
        switch ($Identity) {
            $SchemaNC { return [pscustomobject]@{ objectVersion = 88 } }
            $DomainDN {
                return [pscustomobject]@{
                    DistinguishedName = $DomainDN; Name = 'sub'; ObjectClass = 'domainDNS'; objectSid = 'S-1-5-21-1-2-3'
                    'ms-DS-MachineAccountQuota' = 10; gPLink = '[LDAP://cn={31B2F340-016D-11D2-945F-00C04FB984F9},cn=policies,cn=system,DC=sub,DC=local;0]'
                    gPOptions = 0; whenCreated = [datetime]'2020-01-01'; nTSecurityDescriptor = $RootSd
                }
            }
            "CN=AdminSDHolder,CN=System,$DomainDN" {
                return [pscustomobject]@{ DistinguishedName = $Identity; Name = 'AdminSDHolder'; ObjectClass = 'container'; nTSecurityDescriptor = (New-MockSd @((New-MockAce 'S-1-5-21-1-2-3-1105' 'WriteDacl'))) }
            }
            $Pks { return [pscustomobject]@{ DistinguishedName = $Pks; Name = 'Public Key Services'; ObjectClass = 'container'; nTSecurityDescriptor = (New-MockSd @()) } }
            default { throw "Cannot find an object with identity: '$Identity'" }
        }
    }
    if ($SearchBase -eq $SchemaNC -and $LDAPFilter -like '(|(lDAPDisplayName=*') {
        foreach ($n in 'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'msDS-SupportedEncryptionTypes',
            'msDS-KeyCredentialLink', 'mS-DS-ConsistencyGuid', 'altSecurityIdentities', 'msLAPS-PasswordExpirationTime') {
            [pscustomobject]@{ lDAPDisplayName = $n }
        }
        return
    }
    if ($SearchBase -eq $SchemaNC) {
        [pscustomobject]@{ lDAPDisplayName = 'member'; schemaIDGUID = ([guid]'bf9679c0-0de6-11d0-a285-00aa003049e2').ToByteArray(); ObjectClass = 'attributeSchema' }
        [pscustomobject]@{ lDAPDisplayName = 'user'; schemaIDGUID = ([guid]'bf967aba-0de6-11d0-a285-00aa003049e2').ToByteArray(); ObjectClass = 'classSchema' }
        return
    }
    if ($SearchBase -eq "CN=Extended-Rights,$ConfigNC") {
        [pscustomobject]@{ Name = 'DS-Replication-Get-Changes-All'; rightsGuid = $DcsyncGuid.ToString(); validAccesses = 256 }
        [pscustomobject]@{ Name = 'Certificate-Enrollment'; rightsGuid = $EnrollGuid.ToString(); validAccesses = 256 }
        return
    }
    if ($SearchBase -eq $Pks) {
        [pscustomobject]@{ DistinguishedName = "CN=NTAuthCertificates,$Pks"; Name = 'NTAuthCertificates'; ObjectClass = 'certificationAuthority'; cACertificate = @([byte[]](1, 2, 3)); nTSecurityDescriptor = (New-MockSd @()) }
        return
    }
    if ($SearchBase -eq "CN=Enrollment Services,$Pks") {
        [pscustomobject]@{
            DistinguishedName = "CN=SUB-CA,CN=Enrollment Services,$Pks"; Name = 'SUB-CA'; displayName = 'SUB-CA'; dNSHostName = 'ca01.sub.local'
            certificateTemplates = @('User', 'VulnTemplate'); flags = 10; nTSecurityDescriptor = (New-MockSd @())
        }
        return
    }
    if ($SearchBase -eq "CN=Certificate Templates,$Pks") {
        [pscustomobject]@{
            DistinguishedName = "CN=VulnTemplate,CN=Certificate Templates,$Pks"; Name = 'VulnTemplate'; displayName = 'Vuln Template'
            'msPKI-Certificate-Name-Flag' = 1; 'msPKI-Enrollment-Flag' = 0; 'msPKI-RA-Signature' = 0
            pKIExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2'); 'msPKI-Template-Schema-Version' = 2
            nTSecurityDescriptor = (New-MockSd @((New-MockAce 'S-1-5-11' 'ExtendedRight' $EnrollGuid)))
        }
        [pscustomobject]@{
            DistinguishedName = "CN=Unpublished,CN=Certificate Templates,$Pks"; Name = 'Unpublished'; displayName = 'Unpublished'
            'msPKI-Certificate-Name-Flag' = -2113929216; 'msPKI-Enrollment-Flag' = 2; pKIExtendedKeyUsage = @('1.3.6.1.5.5.7.3.1')
            nTSecurityDescriptor = (New-MockSd @())
        }
        return
    }
    # ACL 查詢
    switch -Wildcard ($LDAPFilter) {
        '(objectClass=organizationalUnit)' { [pscustomobject]@{ DistinguishedName = "OU=Staff,$DomainDN"; ObjectClass = 'organizationalUnit'; nTSecurityDescriptor = (New-MockSd @((New-MockAce 'S-1-5-21-1-2-3-1105' 'CreateChild'))) } }
        '(adminCount=1)' {
            [pscustomobject]@{ DistinguishedName = $UserJdoeDn; ObjectClass = 'user'; objectSid = 'S-1-5-21-1-2-3-1105'; sAMAccountName = 'jdoe'; nTSecurityDescriptor = (New-MockSd @()) }
            [pscustomobject]@{ DistinguishedName = "OU=Staff,$DomainDN"; ObjectClass = 'organizationalUnit'; nTSecurityDescriptor = (New-MockSd @()) }
        }
        '*primaryGroupID=516*' { [pscustomobject]@{ DistinguishedName = "CN=DC01,OU=Domain Controllers,$DomainDN"; ObjectClass = 'computer'; objectSid = 'S-1-5-21-1-2-3-1000'; sAMAccountName = 'DC01$'; nTSecurityDescriptor = (New-MockSd @()) } }
        default { }
    }
}

# ---------------------------------------------------------------------------
# Mock：GroupPolicy
# ---------------------------------------------------------------------------
$GpoId = [guid]'31B2F340-016D-11D2-945F-00C04FB984F9'
function Get-GPO {
    [CmdletBinding()] param([switch] $All, $Domain, $Server)
    [pscustomobject]@{
        Id = $GpoId; DisplayName = 'Default Domain Policy'; GpoStatus = 'AllSettingsEnabled'; Owner = 'SUB\Domain Admins'
        CreationTime = [datetime]'2020-01-01'; ModificationTime = [datetime]'2026-09-01'; WmiFilter = $null; Description = ''
        User = [pscustomobject]@{ DSVersion = 0; SysvolVersion = 0 }; Computer = [pscustomobject]@{ DSVersion = 3; SysvolVersion = 3 }
    }
}
function Get-GPOReport {
    [CmdletBinding()] param($Guid, $ReportType, $Domain, $Server)
    "<GPO><Name>Default Domain Policy</Name><Member>SUB\jdoe</Member><Member>john.doe@sub.com</Member><Member>John Doe</Member></GPO>"
}

# ---------------------------------------------------------------------------
# Mock：ADSync / 本機
# ---------------------------------------------------------------------------
function Get-ADSyncScheduler { [pscustomobject]@{ SyncCycleEnabled = $true; StagingModeEnabled = $false; AllowedSyncCycleInterval = [timespan]::FromMinutes(30) } }
function Get-ADSyncAADCompanyFeature { [pscustomobject]@{ PasswordHashSync = $true; UserWriteback = $false; DeviceWriteback = $false } }
function Get-ADSyncConnector {
    [pscustomobject]@{
        Name = 'sub.local'; Identifier = [guid]::NewGuid(); Type = 'AD'; Subtype = $null; Version = 5
        ConnectivityParameters = @(
            [pscustomobject]@{ Name = 'forest-name'; Value = 'sub.local' },
            [pscustomobject]@{ Name = 'forest-login-user'; Value = 'MSOL_abc123' },
            [pscustomobject]@{ Name = 'forest-login-password'; Value = 'MUST-NOT-LEAK' }
        )
        Partitions = @([pscustomobject]@{ Name = 'DC=sub,DC=local'; DN = 'DC=sub,DC=local'; Selected = $true
                ConnectorPartitionScope = [pscustomobject]@{ ContainerInclusionList = @('OU=Staff,DC=sub,DC=local'); ContainerExclusionList = @() } })
        ObjectInclusionList = @('user', 'group')
    }
}
function Get-ADSyncAADPasswordSyncConfiguration { [CmdletBinding()] param($SourceConnector) [pscustomobject]@{ Enabled = $true } }
function Get-ADSyncServerConfiguration {
    [CmdletBinding()] param($Path)
    New-Item -ItemType Directory -Path (Join-Path $Path 'Connectors') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $Path 'Connectors/Connector_sub.local.xml') -Value '<connector name="sub.local"/>'
}
function Get-LocalGroupMember {
    [CmdletBinding()] param($SID, $Name)
    if ($Name -eq 'ADSyncAdmins') { throw 'Group ADSyncAdmins was not found.' }
    [pscustomobject]@{ Name = 'SUB\jdoe'; SID = 'S-1-5-21-1-2-3-1105'; ObjectClass = 'User'; PrincipalSource = 'ActiveDirectory' }
    [pscustomobject]@{ Name = 'SUB\Domain Admins'; SID = 'S-1-5-21-1-2-3-512'; ObjectClass = 'Group'; PrincipalSource = 'ActiveDirectory' }
}
function Get-CimInstance { [CmdletBinding()] param($ClassName, $Filter) [pscustomobject]@{ StartName = 'NT SERVICE\ADSync'; State = 'Running' } }

# ---------------------------------------------------------------------------
# Mock：Microsoft Graph
# ---------------------------------------------------------------------------
function Connect-MgGraph {
    [CmdletBinding()] param([string[]] $Scopes, $TenantId, $ClientId, $ContextScope, [switch] $NoWelcome, [switch] $UseDeviceCode)
    $script:MockGraphScopes = $Scopes
}
function Get-MgContext { [pscustomobject]@{ TenantId = 'tid-123'; Account = 'auditor@sub.com'; Scopes = $script:MockGraphScopes } }
function Disconnect-MgGraph { }

$GraphResponses = [ordered]@{
    'v1.0/organization*'                             = '{"value":[{"id":"tid-123","displayName":"Sub A Co","onPremisesSyncEnabled":true}]}'
    'v1.0/domains*'                                  = '{"value":[{"id":"sub.com","authenticationType":"Managed","isVerified":true}]}'
    'v1.0/users?$top=999&$select=id,signInActivity'  = '{"value":[]}'
    '*users?page2'                                   = '{"value":[{"id":"u2","userPrincipalName":"alice_gmail.com#EXT#@subtenant.onmicrosoft.com","displayName":"Alice Wang","userType":"Guest","otherMails":["alice@gmail.com"]},{"id":"u3","userPrincipalName":"Sync_AADC01_abc@subtenant.onmicrosoft.com","displayName":"On-Premises Directory Synchronization Service Account"}]}'
    'v1.0/users?*'                                   = '{"value":[{"id":"u1","userPrincipalName":"jdoe@sub.com","displayName":"John Doe","givenName":"John","surname":"Doe","mail":"john.doe@sub.com","onPremisesSamAccountName":"jdoe","onPremisesSecurityIdentifier":"S-1-5-21-1-2-3-1105","onPremisesDistinguishedName":"CN=John Doe,OU=Staff,DC=sub,DC=local","signInActivity":{"lastSignInDateTime":"2026-10-01T00:00:00Z"}}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/users?page2"}'
    'v1.0/groups/g1/transitiveMembers*'              = '{"value":[{"@odata.type":"#microsoft.graph.user","id":"u1"}]}'
    'v1.0/groups/*/owners*'                          = '{"value":[]}'
    'v1.0/groups/*/transitiveMembers*'               = '{"value":[]}'
    'v1.0/groups?*'                                  = '{"value":[{"id":"g1","displayName":"Tier0 Admins","isAssignableToRole":true},{"id":"g2","displayName":"CA Exclusions","isAssignableToRole":false},{"id":"g3","displayName":"All Staff","isAssignableToRole":false}]}'
    'v1.0/roleManagement/directory/roleDefinitions*' = '{"value":[{"id":"62e90394-69f5-4237-9190-012177145e10","displayName":"Global Administrator","isBuiltIn":true}]}'
    'v1.0/roleManagement/directory/roleAssignments*' = '{"value":[{"id":"ra1","principalId":"g1","roleDefinitionId":"62e90394-69f5-4237-9190-012177145e10","directoryScopeId":"/"},{"id":"ra2","principalId":"u1","roleDefinitionId":"62e90394-69f5-4237-9190-012177145e10","directoryScopeId":"/"}]}'
    'v1.0/roleManagement/directory/roleEligibilitySchedules*' = 'THROW:Response status code does not indicate success: Forbidden (Forbidden).'
    'v1.0/roleManagement/directory/roleAssignmentSchedules*'  = '{"value":[]}'
    'v1.0/directory/administrativeUnits/au1/scopedRoleMembers' = '{"value":[{"id":"srm1","roleId":"r1","administrativeUnitId":"au1","roleMemberInfo":{"id":"u1","displayName":"John Doe"}}]}'
    'v1.0/directory/administrativeUnits?*'           = '{"value":[{"id":"au1","displayName":"Taipei Office"}]}'
    'v1.0/identity/conditionalAccess/policies'       = '{"value":[{"id":"ca1","displayName":"Require MFA","state":"enabled","conditions":{"users":{"includeUsers":["All"],"includeGroups":[],"excludeGroups":["g2"]}}}]}'
    'v1.0/identity/conditionalAccess/namedLocations' = '{"value":[]}'
    'v1.0/policies/authorizationPolicy'              = '{"@odata.context":"x","id":"authorizationPolicy","displayName":"Authorization Policy","defaultUserRolePermissions":{"allowedToCreateApps":true}}'
    'v1.0/policies/identitySecurityDefaultsEnforcementPolicy' = '{"id":"00000000-0000-0000-0000-000000000005","displayName":"Security Defaults","isEnabled":false}'
    'v1.0/policies/authenticationMethodsPolicy'      = '{"id":"authenticationMethodsPolicy","displayName":"Authentication Methods Policy","policyVersion":"1.5"}'
    'v1.0/reports/authenticationMethods/userRegistrationDetails' = '{"value":[{"id":"u1","userPrincipalName":"jdoe@sub.com","userDisplayName":"John Doe","isMfaRegistered":true,"isAdmin":true}]}'
    'v1.0/devices*'                                  = '{"value":[{"id":"d1","displayName":"WS01","trustType":"ServerAd"}]}'
    'v1.0/applications/a1/owners*'                   = '{"value":[{"@odata.type":"#microsoft.graph.user","id":"u1"}]}'
    'v1.0/applications?*'                            = '{"value":[{"id":"a1","appId":"app-1","displayName":"HR Portal","passwordCredentials":[{"keyId":"k1","hint":"abc","endDateTime":"2027-01-01T00:00:00Z","secretText":null}],"keyCredentials":[{"keyId":"k2","key":"MIIBMUSTNOTLEAK","customKeyIdentifier":"AB"}]}]}'
    'v1.0/servicePrincipals/sp1/owners*'             = '{"value":[]}'
    'v1.0/servicePrincipals/sp1/appRoleAssignments'  = '{"value":[{"id":"ara1","appRoleId":"9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8","principalId":"sp1","principalDisplayName":"HR Portal","resourceId":"sp-graph","resourceDisplayName":"Microsoft Graph"}]}'
    'v1.0/servicePrincipals/sp-mi/appRoleAssignments' = '{"value":[{"id":"ara2","appRoleId":"9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8","principalId":"sp-mi","principalDisplayName":"mi-automation","resourceId":"sp-graph","resourceDisplayName":"Microsoft Graph"}]}'
    'v1.0/servicePrincipals/sp-graph?*'              = '{"id":"sp-graph","appId":"00000003-0000-0000-c000-000000000000","displayName":"Microsoft Graph","appRoles":[{"id":"9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8","value":"RoleManagement.ReadWrite.Directory","allowedMemberTypes":["Application"],"isEnabled":true,"description":"long text"}],"oauth2PermissionScopes":[{"id":"e1fe6dd8-ba31-4d61-89e7-88639da4683d","value":"User.Read","type":"User","isEnabled":true}]}'
    'v1.0/servicePrincipals?*'                       = '{"value":[{"id":"sp1","appId":"app-1","displayName":"HR Portal","appOwnerOrganizationId":"tid-123","servicePrincipalType":"Application"},{"id":"sp-graph","appId":"00000003-0000-0000-c000-000000000000","displayName":"Microsoft Graph","appOwnerOrganizationId":"f8cdef31-a31e-4b4a-93e4-5f571e91255a","servicePrincipalType":"Application"},{"id":"sp-mi","displayName":"mi-automation","appOwnerOrganizationId":"f8cdef31-a31e-4b4a-93e4-5f571e91255a","servicePrincipalType":"ManagedIdentity"}]}'
    'v1.0/oauth2PermissionGrants'                    = '{"value":[{"id":"o1","clientId":"sp1","consentType":"AllPrincipals","resourceId":"sp-graph","scope":"User.Read"}]}'
    'v1.0/identityProtection/riskyUsers'             = '{"value":[{"id":"u1","userPrincipalName":"jdoe@sub.com","userDisplayName":"John Doe","riskLevel":"medium"}]}'
    'v1.0/auditLogs/signIns*'                        = '{"value":[{"id":"s1","createdDateTime":"2026-10-12T00:00:00Z","userPrincipalName":"jdoe@sub.com","userDisplayName":"John Doe","appDisplayName":"Office 365","ipAddress":"203.0.113.5","status":{"errorCode":0}}]}'
    'v1.0/auditLogs/directoryAudits*'                = '{"value":[{"id":"da1","activityDisplayName":"Add member to role","initiatedBy":{"user":{"userPrincipalName":"admin@sub.com"}},"targetResources":[{"type":"User","userPrincipalName":"jdoe@sub.com","displayName":"John Doe"}]}]}'
    'v1.0/identityProtection/riskDetections*'        = '{"value":[]}'
}
$script:GraphCalls = New-Object System.Collections.Generic.List[string]
function Invoke-MgGraphRequest {
    [CmdletBinding()] param($Method, [string] $Uri, $OutputType)
    $script:GraphCalls.Add($Uri)
    foreach ($k in $GraphResponses.Keys) {
        if ($Uri -like $k) {
            $v = $GraphResponses[$k]
            if ($v.StartsWith('THROW:')) { throw $v.Substring(6) }
            return ($v | ConvertFrom-Json)
        }
    }
    throw "Mock Graph: 未定義的 URI $Uri"
}

# ---------------------------------------------------------------------------
# Mock：Get-WinEvent
# ---------------------------------------------------------------------------
function Get-WinEvent {
    [CmdletBinding()] param($ComputerName, $FilterHashtable, $MaxEvents, $Credential)
    if ($FilterHashtable.Id -ne 4769) { throw 'No events were found that match the specified selection criteria.' }
    $evt = [pscustomobject]@{
        Id = 4769; RecordId = 42; TimeCreated = [datetime]'2026-10-12T08:00:00'; MachineName = 'dc01.sub.local'
        Keywords = [long]-9214364837600034816
    }
    $evt | Add-Member -MemberType ScriptMethod -Name ToXml -Value {
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData>' +
        '<Data Name="TargetUserName">jdoe@SUB.LOCAL</Data><Data Name="ServiceName">MSSQLSvc/sql01.sub.local:1433</Data>' +
        '<Data Name="TicketEncryptionType">0x17</Data><Data Name="IpAddress">::ffff:10.0.0.50</Data><Data Name="SubjectUserName">jdoe</Data></EventData></Event>'
    }
    $evt
}

# ---------------------------------------------------------------------------
# 執行
# ---------------------------------------------------------------------------
$result = Invoke-ADHDMain
$bundle = $result.BundlePath

# ---------------------------------------------------------------------------
# 驗證
# ---------------------------------------------------------------------------
$failures = New-Object System.Collections.Generic.List[string]
function Assert-True { param([bool] $Condition, [string] $Message) if (-not $Condition) { $failures.Add($Message); Write-Host "FAIL  $Message" -ForegroundColor Red } else { Write-Host "ok    $Message" } }
function Read-Dataset { param([string] $Name) @(Get-Content -LiteralPath (Join-Path $bundle "$Name.jsonl") -Encoding UTF8 | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json }) }

$manifest = Get-Content -LiteralPath (Join-Path $bundle 'manifest.json') -Raw | ConvertFrom-Json
Assert-True ($manifest.schema -eq 'adhd.collect/1') 'manifest schema'
Assert-True ($manifest.pseudonymization.enabled -eq $true) '假名化預設啟用'
Assert-True ($manifest.scope.entraTenantId -eq 'tid-123') 'manifest 記錄 tenant'

$status = @{}
foreach ($d in $manifest.datasets) { $status[$d.name] = $d.status }
$expectedError = @('gpo_gpp_cpassword', 'entra_pim_eligibility')
foreach ($d in $manifest.datasets) {
    if ($expectedError -contains $d.name) { Assert-True ($d.status -eq 'error') "$($d.name) 預期為 error（模擬環境）" }
    else { Assert-True ($d.status -eq 'ok') "$($d.name) 狀態 ok（實際 $($d.status)：$($d.message)）" }
    if ($d.format -eq 'jsonl' -and $d.file) {
        $path = Join-Path $bundle $d.file
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-True ($hash -eq $d.sha256) "$($d.name) sha256 一致"
        $lines = @(Get-Content -LiteralPath $path -Encoding UTF8 | Where-Object { $_ }).Count
        Assert-True ($lines -eq $d.records) "$($d.name) 筆數一致（$lines）"
    }
}
foreach ($n in 'ad_users', 'ad_groups', 'ad_acls', 'adcs_templates', 'entra_users', 'entra_group_memberships', 'dc_security_events', 'entraconnect_connectors', 'gpo_reports', 'entraconnect_config') {
    Assert-True ($status.ContainsKey($n)) "資料集 $n 存在"
}

# 每一行都是合法 JSON（ConvertFrom-Json 已在 Read-Dataset 驗證）
$users = Read-Dataset 'ad_users'
$jdoe = $users | Where-Object { $_.sid -eq 'S-1-5-21-1-2-3-1105' }
Assert-True ($users.Count -eq 4) 'ad_users 4 筆'
Assert-True ($jdoe.samAccountName -match '^u-[0-9a-f]{12}$') 'jdoe 帳號被假名化'
Assert-True ($jdoe.userPrincipalName -match '^u-[0-9a-f]{12}@sub\.local$') 'UPN 假名保留網域'
Assert-True ($jdoe.distinguishedName -match '^CN=u-[0-9a-f]{12},OU=Staff,DC=sub,DC=local$') 'DN 第一段被假名化、OU 路徑保留'
Assert-True ($jdoe.descriptionHasSecretHint -eq $true) 'description 密碼提示旗標'
Assert-True (@($jdoe.uacFlags) -contains 'DONT_REQ_PREAUTH') 'UAC 旗標解析（AS-REP roastable）'
Assert-True ($jdoe.department -eq 'IT') 'department 不受名稱碰撞影響'
Assert-True ($jdoe.consistencyGuid -eq '11111111-2222-3333-4444-555555555555') 'mS-DS-ConsistencyGuid 轉換'
Assert-True (($users | Where-Object { $_.sid -like '*-500' }).samAccountName -eq 'Administrator') '內建帳號不假名化'
Assert-True (($users | Where-Object { $_.sid -like '*-1106' }).samAccountName -eq 'MSOL_abc123') '同步基礎設施帳號不假名化'

$groups = Read-Dataset 'ad_groups'
$da = $groups | Where-Object { $_.name -eq 'Domain Admins' }
Assert-True (@($da.members) -contains 'S-1-5-21-1-2-3-1105') '群組成員解析為 SID'
Assert-True (@($da.members) -contains 'S-1-5-21-9-9-9-1000') 'FSP 成員解析為外部 SID'
$it = $groups | Where-Object { $_.name -eq 'IT Staff' }
Assert-True (@($it.members) -contains 'S-1-5-21-1-2-3-1201') '電腦成員解析為 SID'
Assert-True ((@($it.members) | Where-Object { $_ -like 'DN:*' }).Count -eq 1) '未知成員保留 DN'
Assert-True ($it.managedBy -match '^CN=u-[0-9a-f]{12},') 'managedBy 的使用者 DN 被假名化'

$gmsa = Read-Dataset 'ad_service_accounts'
Assert-True (@($gmsa[0].principalsAllowedToRetrievePassword) -contains 'S-1-5-21-1-2-3-1200') 'gMSA 可讀密碼的主體解析為 SID'

$computers = Read-Dataset 'ad_computers'
Assert-True (($computers | Where-Object { $_.name -eq 'DC01' }).isDomainController -eq $true) 'DC 判斷'
Assert-True (($computers | Where-Object { $_.name -eq 'WS01' }).hasLaps -eq $true) 'Windows LAPS 到期時間 → hasLaps'

$ous = Read-Dataset 'ad_ous'
$staff = $ous | Where-Object { $_.name -eq 'Staff' }
Assert-True ($staff.gpLinks[0].enforced -eq $true -and $staff.blockInheritance -eq $true) 'gPLink / 封鎖繼承解析'

$acls = Read-Dataset 'ad_acls'
$root = $acls | Where-Object { $_.reason -eq 'domainRoot' }
Assert-True ((@($root.aces) | Where-Object { $_.objectTypeName -eq 'DS-Replication-Get-Changes-All' }).Count -eq 1) 'DCSync 權限 GUID 解析'
Assert-True ((@($acls) | Where-Object { $_.distinguishedName -eq "OU=Staff,$DomainDN" }).Count -eq 1) 'ACL 目標去重'
Assert-True ((@($acls) | Where-Object { $_.reason -eq 'adminCount' }).samAccountName -match '^u-') 'ACL 目標使用者帳號假名化'

$tpl = Read-Dataset 'adcs_templates'
$vuln = $tpl | Where-Object { $_.name -eq 'VulnTemplate' }
Assert-True ($vuln.published -and $vuln.enrolleeSuppliesSubject -and $vuln.clientAuthCapable -and -not $vuln.managerApproval) 'ESC1 相關旗標'
Assert-True ((@($vuln.aces) | Where-Object { $_.objectTypeName -eq 'Certificate-Enrollment' }).Count -eq 1) '範本 Enroll 權限解析'
Assert-True (($tpl | Where-Object { $_.name -eq 'Unpublished' }).published -eq $false) '未發佈範本'

$eu = Read-Dataset 'entra_users'
Assert-True ($eu.Count -eq 3) 'Graph 分頁（3 位使用者）'
$eJdoe = $eu | Where-Object { $_.id -eq 'u1' }
Assert-True ($eJdoe.displayName -eq $jdoe.displayName) 'AD 與 Entra 的同一 displayName 假名一致'
Assert-True ($eJdoe.onPremisesSecurityIdentifier -eq 'S-1-5-21-1-2-3-1105') 'onPremisesSecurityIdentifier 保留（混合關聯）'
Assert-True ($null -ne $eJdoe.signInActivity) 'signInActivity 已收集'
Assert-True ((($eu | Where-Object { $_.id -eq 'u2' }).userPrincipalName) -match '^u-[0-9a-f]{12}@subtenant\.onmicrosoft\.com$') 'Guest UPN 假名化'

$gm = Read-Dataset 'entra_group_memberships'
Assert-True (($gm | ForEach-Object { $_.groupId } | Sort-Object) -join ',' -eq 'g1,g2') '只收角色 / CA 相關群組成員'

$apps = Read-Dataset 'entra_applications'
Assert-True ($null -eq $apps[0].passwordCredentials[0].PSObject.Properties['hint']) 'App secret hint 被移除'
Assert-True ($null -eq $apps[0].keyCredentials[0].PSObject.Properties['key']) 'App 憑證 key 被移除'
Assert-True ($apps[0].passwordCredentials[0].keyId -eq 'k1') 'credential keyId 保留'

$ara = Read-Dataset 'entra_app_role_assignments'
Assert-True ($ara.Count -eq 2) 'App role assignments：租戶 App + Managed Identity'
$cat = Read-Dataset 'entra_permission_catalog'
Assert-True ($cat[0].appRoles[0].value -eq 'RoleManagement.ReadWrite.Directory') '權限目錄解析'
Assert-True ($null -eq $cat[0].appRoles[0].PSObject.Properties['description']) '權限目錄已精簡'

$ca = Read-Dataset 'entra_ca_policies'
Assert-True ($ca[0].displayName -eq 'Require MFA') 'CA 名稱保留'

$sign = Read-Dataset 'entra_signins'
Assert-True ($sign[0].userPrincipalName -match '^u-[0-9a-f]{12}@sub\.com$' -and $sign[0].userDisplayName -match '^u-') '登入紀錄假名化'
Assert-True ($sign[0].appDisplayName -eq 'Office 365') '登入紀錄 App 名稱保留'

$ev = Read-Dataset 'dc_security_events'
Assert-True ($ev.Count -eq 1 -and $ev[0].outcome -eq 'success') 'DC 事件解析'
Assert-True ($ev[0].data.SubjectUserName -match '^u-' -and $ev[0].data.TargetUserName -match '^u-[0-9a-f]{12}@sub\.local$') 'DC 事件帳號假名化'

$conn = Read-Dataset 'entraconnect_connectors'
Assert-True ($conn[0].connectivityParameters.'forest-login-user' -eq 'MSOL_abc123') 'AD DS connector 帳號保留'
Assert-True ($null -eq $conn[0].connectivityParameters.PSObject.Properties['forest-login-password']) 'connector 密碼參數被移除'
$srv = Read-Dataset 'entraconnect_server'
Assert-True ($srv[0].localAdministrators[0].name -match '^SUB\\u-[0-9a-f]{12}$') '本機管理員帳號假名化'

$xmlText = Get-Content -LiteralPath (Join-Path $bundle "gpo_reports/$($GpoId.ToString().ToLowerInvariant()).xml") -Raw
Assert-True ($xmlText -notmatch 'jdoe|john\.doe|John Doe') 'GPO XML 假名化'

# 全文掃描：不應出現的明文
$allText = (Get-ChildItem -LiteralPath $bundle -Recurse -File | Where-Object { $_.Name -ne 'collection.log' } | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
foreach ($bad in 'MUST-NOT-LEAK', 'MUSTNOTLEAK', 'Kq#Zx!7w', 'jdoe', 'John Doe', 'john.doe@sub.com', 'Alice Wang', 'alice@gmail.com', '"hint"', '"secretText"') {
    Assert-True ($allText.IndexOf($bad, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) "bundle 不含 $bad"
}
$logText = Get-Content -LiteralPath (Join-Path $bundle 'collection.log') -Raw
Assert-True ($logText -notmatch 'john\.doe@sub\.com') 'collection.log 不含使用者 email'

Assert-True ($null -ne $result.ZipPath -and (Test-Path -LiteralPath $result.ZipPath)) '產生 zip'
$keyFile = Join-Path $OutputRoot 'ADHD-pseudonym.key'
Assert-True (Test-Path -LiteralPath $keyFile) '假名化金鑰在 bundle 外'
Assert-True (@(Get-ChildItem -LiteralPath $OutputRoot -Filter 'ADHD-pseudonym-map-*.csv').Count -eq 1) '對照表在 bundle 外'
Assert-True (-not (Test-Path -LiteralPath (Join-Path $bundle 'ADHD-pseudonym.key'))) 'bundle 內沒有金鑰'

# ---------------------------------------------------------------------------
# 第二次執行：只跑 EntraConnect（模擬 Entra Connect 伺服器：沒有 AD 使用者清單），沿用同一把金鑰
# ---------------------------------------------------------------------------
$firstJdoe = $jdoe.samAccountName
$Include = @('EntraConnect')
$Label = 'SmokeSub-AADC'
$PseudonymKeyFile = $keyFile
$script:ADHDTestHooks.AvailableModules = @('ADSync')
function Get-ADSyncConnector {
    [pscustomobject]@{
        Name = 'sub.local'; Identifier = [guid]::NewGuid(); Type = 'AD'; Version = 5; CreationTime = [datetime]'2024-01-01'
        ConnectivityParameters = @(
            [pscustomobject]@{ Name = 'forest-name'; Value = 'sub.local' },
            [pscustomobject]@{ Name = 'forest-login-user'; Value = 'jdoe' },
            [pscustomobject]@{ Name = 'forest-login-domain'; Value = 'SUB' }
        )
        Partitions = @(); ObjectInclusionList = @('user')
    }
}
function Get-ADSyncServerConfiguration {
    [CmdletBinding()] param($Path)
    New-Item -ItemType Directory -Path (Join-Path $Path 'Connectors') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $Path 'Connectors/Connector_sub.local.xml') -Value '<connector name="sub.local"><parameter name="forest-login-user">jdoe</parameter><owner>SUB\jdoe</owner></connector>'
}
$result2 = Invoke-ADHDMain
$bundle2 = $result2.BundlePath
$m2 = Get-Content -LiteralPath (Join-Path $bundle2 'manifest.json') -Raw | ConvertFrom-Json
Assert-True ($m2.pseudonymization.keyId -eq $manifest.pseudonymization.keyId) 'AADC 單獨執行：沿用同一把金鑰'
$srv2 = @(Get-Content -LiteralPath (Join-Path $bundle2 'entraconnect_server.jsonl') -Encoding UTF8 | ConvertFrom-Json)
Assert-True ($srv2[0].localAdministrators[0].name -eq "SUB\$firstJdoe") 'AADC 單獨執行：本機管理員帳號假名化，且與 AD bundle 一致'
Assert-True ($srv2[0].localAdministrators[1].name -eq 'SUB\Domain Admins') 'AADC 單獨執行：群組名稱保留'
$conn2 = @(Get-Content -LiteralPath (Join-Path $bundle2 'entraconnect_connectors.jsonl') -Encoding UTF8 | ConvertFrom-Json)
Assert-True ($conn2[0].connectivityParameters.'forest-login-user' -eq $firstJdoe) 'AADC 單獨執行：connector 帳號假名化，且與 AD bundle 一致'
$cfg2 = Get-Content -LiteralPath (Join-Path $bundle2 'entraconnect_config/Connectors/Connector_sub.local.xml') -Raw
Assert-True ($cfg2 -match [regex]::Escape(">$firstJdoe<") -and $cfg2 -match [regex]::Escape(">SUB\$firstJdoe<")) 'AADC 單獨執行：entraconnect_config 已假名化'
$all2 = (Get-ChildItem -LiteralPath $bundle2 -Recurse -File | Where-Object { $_.Name -ne 'collection.log' } | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
Assert-True ($all2.IndexOf('jdoe', [System.StringComparison]::OrdinalIgnoreCase) -lt 0) 'AADC 單獨執行：bundle 不含 jdoe 明文'
$dsMap = @{}; foreach ($d in $m2.datasets) { $dsMap[$d.name] = $d }
Assert-True ($dsMap['entraconnect_config'].files[0].sha256 -eq (Get-FileHash -LiteralPath (Join-Path $bundle2 'entraconnect_config/Connectors/Connector_sub.local.xml') -Algorithm SHA256).Hash.ToLowerInvariant()) 'AADC 單獨執行：假名化後的 config 雜湊與 manifest 一致'

Write-Host ''
if ($failures.Count -gt 0) {
    Write-Host ("{0} 項失敗" -f $failures.Count) -ForegroundColor Red
    exit 1
}
Write-Host '全部通過' -ForegroundColor Green
Write-Output $result.ZipPath
