"""Well-known identifiers used by the loader and the rules."""
from __future__ import annotations

WELL_KNOWN_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-3-0": "CREATOR OWNER",
    "S-1-5-7": "ANONYMOUS LOGON",
    "S-1-5-9": "ENTERPRISE DOMAIN CONTROLLERS",
    "S-1-5-10": "SELF",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "SYSTEM",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicator",
    "S-1-5-32-554": "Pre-Windows 2000 Compatible Access",
    "S-1-5-32-560": "Windows Authorization Access Group",
    "S-1-5-32-561": "Terminal Server License Servers",
}

DOMAIN_RIDS = {
    498: "Enterprise Read-only Domain Controllers",
    500: "Administrator",
    501: "Guest",
    502: "krbtgt",
    512: "Domain Admins",
    513: "Domain Users",
    514: "Domain Guests",
    515: "Domain Computers",
    516: "Domain Controllers",
    517: "Cert Publishers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    521: "Read-only Domain Controllers",
    525: "Protected Users",
    526: "Key Admins",
    527: "Enterprise Key Admins",
    553: "RAS and IAS Servers",
}

# Groups whose members control the domain (Tier 0). Operators are included: each has a known
# path to domain compromise (logon to DCs, backup of NTDS, service / driver installation).
TIER0_DOMAIN_RIDS = {512, 516, 518, 519, 521, 498, 526, 527}
TIER0_BUILTIN_SIDS = {"S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551"}
OPERATOR_SIDS = {"S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551"}
TIER0_GROUP_NAMES = {"dnsadmins"}  # no fixed RID

# Principals that legitimately hold rights on Tier0 objects and are not "people".
SAFE_ACL_PRINCIPALS = {"S-1-5-18", "S-1-5-9", "S-1-3-0", "S-1-5-10"}

# "Everyone-ish" principals: rights granted to these are available to any user / computer.
BROAD_SIDS = {"S-1-1-0", "S-1-5-7", "S-1-5-11", "S-1-5-32-545"}
BROAD_DOMAIN_RIDS = {513, 515}

# --- Entra ID -------------------------------------------------------------------------------
# Directory roles that control the tenant (templateId -> name).
ENTRA_TIER0_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "8329153b-31d0-4727-b945-745eb3bc5f31": "Domain Name Administrator",
    "d29b2b05-8046-44ba-8758-1e26182fcf32": "Directory Synchronization Accounts",
}
# Highly privileged but scoped roles.
ENTRA_HIGH_ROLES = {
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "fdd7a751-b60b-444a-984c-02652fe8fa1c": "Groups Administrator",
    "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "69091246-20e8-4a56-aa4d-066075b2a7a8": "Teams Administrator",
    "be2f45a1-457d-42af-a067-6ec1fa63bc45": "External Identity Provider Administrator",
}
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
DIRECTORY_SYNC_ROLE = "d29b2b05-8046-44ba-8758-1e26182fcf32"

MICROSOFT_TENANTS = {"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"}
# Microsoft first-party public clients whose service principal owner tenant varies between tenants.
MICROSOFT_FIRST_PARTY_APPIDS = {
    "14d82eec-204b-4c2f-b7e8-296a70dab67e",  # Microsoft Graph Command Line Tools
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Microsoft Azure CLI
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Microsoft Azure PowerShell
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office
}
# Tenant-owned service principals that Entra creates and credentials itself.
SYSTEM_SERVICE_PRINCIPALS = {"P2P Server"}

MS_GRAPH_APPID = "00000003-0000-0000-c000-000000000000"
AAD_GRAPH_APPID = "00000002-0000-0000-c000-000000000000"
EXO_APPID = "00000002-0000-0ff1-ce00-000000000000"

# Application permissions that allow escalation to tenant control.
TIER0_APP_PERMISSIONS = {
    "RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All", "Application.ReadWrite.All",
    "Directory.ReadWrite.All", "UserAuthenticationMethod.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess",
    "PrivilegedAccess.ReadWrite.AzureADGroup", "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup",
    "Domain.ReadWrite.All", "Policy.ReadWrite.AuthenticationMethod", "Organization.ReadWrite.All",
}
# Application permissions with broad data access or account takeover of non-admins.
HIGH_APP_PERMISSIONS = {
    "Mail.ReadWrite", "Mail.Send", "Mail.Read", "Files.ReadWrite.All", "Files.Read.All", "Sites.FullControl.All",
    "Sites.ReadWrite.All", "User.ReadWrite.All", "Group.ReadWrite.All", "GroupMember.ReadWrite.All",
    "Calendars.ReadWrite", "Contacts.ReadWrite", "full_access_as_app", "Exchange.ManageAsApp",
    "Chat.ReadWrite.All", "ChannelMessage.Read.All", "Device.ReadWrite.All", "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementManagedDevices.PrivilegedOperations.All",
}
HIGH_DELEGATED_SCOPES = TIER0_APP_PERMISSIONS | {
    "Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All", "Sites.FullControl.All", "User.ReadWrite.All",
    "Group.ReadWrite.All", "Directory.AccessAsUser.All", "user_impersonation",
}

GUEST_ROLE_SAME_AS_MEMBER = "a0b1b346-4d3e-4e8b-98f8-753987be4970"
GUEST_ROLE_DEFAULT = "10dae51f-b6af-4024-8f8a-0ae1d9d4b8a8"
GUEST_ROLE_RESTRICTED = "2af84b1e-32c8-42b7-82bc-daa82404023b"
