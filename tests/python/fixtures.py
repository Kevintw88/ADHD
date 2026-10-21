"""Synthetic collection rounds for the analysis tests.

`vulnerable_round()` plants at least one instance of every weakness the rules look for;
`clean_round()` is a tidy environment where only informational findings may appear.
Both are written in the collector's own on-disk format (manifest.json + JSONL, schema adhd.collect/1).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

AS_OF = datetime(2026, 10, 15, 8, 0, 0, tzinfo=timezone.utc)
DOM = "S-1-5-21-10-20-30"
DOM_DN = "DC=corp,DC=local"
TENANT = "tenant-0001"
PKS = f"CN=Public Key Services,CN=Services,CN=Configuration,{DOM_DN}"
GA = "62e90394-69f5-4237-9190-012177145e10"
PRA = "e8611ab8-c189-46e8-94e1-60213ab1f814"
SEC_ADMIN = "194ae4cb-b126-40b2-bd5b-6091b380977d"
APP_ADMIN = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
USER_ADMIN = "fe930be7-5e62-47db-91af-98c3a49a38b1"
DCSYNC_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
DCSYNC = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
GPO_DDP = "31b2f340-016d-11d2-945f-00c04fb984f9"
GPO_DDCP = "6ac1786c-016f-11d2-945f-00c04fb984f9"


def ago(days: float | None) -> str | None:
    if days is None:
        return None
    return (AS_OF - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def ahead(days: float) -> str:
    return (AS_OF + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def sid(rid: int) -> str:
    return f"{DOM}-{rid}"


def ace(principal: str, rights: str, ot: str | None = None, otname: str | None = None, inheritance: str = "None",
        inherited: str | None = None) -> dict[str, Any]:
    return {"principal": principal, "type": "Allow", "rights": rights, "objectType": ot, "objectTypeName": otname,
            "inheritedObjectType": None, "inheritedObjectTypeName": inherited, "inheritanceType": inheritance}


def user(rid: int, sam: str, *, enabled=True, flags=("NORMAL_ACCOUNT",), spn=(), logon=5, pwd=30, **extra) -> dict[str, Any]:
    row = {
        "objectClass": "user", "sid": sid(rid), "objectGuid": f"guid-{rid}", "samAccountName": sam,
        "userPrincipalName": f"{sam}@corp.local", "name": sam, "displayName": sam,
        "distinguishedName": f"CN={sam},CN=Users,{DOM_DN}", "enabled": enabled, "isBuiltin": rid < 1000,
        "uacFlags": list(flags) + ([] if enabled else ["ACCOUNTDISABLE"]), "adminCount": None, "primaryGroupId": 513,
        "servicePrincipalNames": list(spn), "sidHistory": [], "pwdLastSet": ago(pwd) if pwd is not None else None,
        "lastLogonTimestamp": ago(logon) if logon is not None else None, "whenCreated": ago(900),
        "allowedToDelegateTo": [], "rbcdAllowedPrincipals": [], "supportedEncryptionTypes": None,
        "keyCredentialLinkCount": 0, "descriptionHasSecretHint": False, "infoHasSecretHint": False,
    }
    row.update(extra)
    return row


def computer(rid: int, name: str, *, os="Windows 11 Enterprise", dc=False, laps=True, flags=("WORKSTATION_TRUST_ACCOUNT",),
             logon=3, pwd=20, ou="OU=Workstations", **extra) -> dict[str, Any]:
    row = {
        "objectClass": "computer", "sid": sid(rid), "name": name, "samAccountName": name + "$",
        "dnsHostName": f"{name.lower()}.corp.local", "distinguishedName": f"CN={name},{ou},{DOM_DN}", "enabled": True,
        "operatingSystem": os, "uacFlags": list(flags), "primaryGroupId": 516 if dc else 515, "isDomainController": dc,
        "pwdLastSet": ago(pwd), "lastLogonTimestamp": ago(logon), "whenCreated": ago(800),
        "servicePrincipalNames": [], "allowedToDelegateTo": [], "rbcdAllowedPrincipals": [], "hasLaps": laps,
        "keyCredentialLinkCount": 0, "sidHistory": [], "descriptionHasSecretHint": False,
    }
    row.update(extra)
    return row


def group(gsid: str, name: str, members=(), **extra) -> dict[str, Any]:
    row = {"objectClass": "group", "sid": gsid, "name": name, "samAccountName": name,
           "distinguishedName": f"CN={name},CN=Users,{DOM_DN}", "members": list(members), "memberCount": len(members),
           "isBuiltin": False, "adminCount": None, "descriptionHasSecretHint": False}
    row.update(extra)
    return row


def write_bundle(root: Path, name: str, datasets: dict[str, Any], *, key_id: str = "testkey1",
                 modules: list[str] | None = None, scope: dict[str, Any] | None = None) -> Path:
    out = root / name
    out.mkdir(parents=True, exist_ok=True)
    entries = []
    for ds, rows in datasets.items():
        if isinstance(rows, tuple):  # ("error", "message")
            entries.append({"name": ds, "module": "x", "file": f"{ds}.jsonl", "format": "jsonl", "records": 0,
                            "sha256": None, "status": rows[0], "message": rows[1]})
            (out / f"{ds}.jsonl").write_text("", encoding="utf-8")
            continue
        text = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
        (out / f"{ds}.jsonl").write_text(text, encoding="utf-8")
        entries.append({"name": ds, "module": "x", "file": f"{ds}.jsonl", "format": "jsonl", "records": len(rows),
                        "sha256": hashlib.sha256(text.encode()).hexdigest(), "status": "ok", "message": None})
    manifest = {
        "schema": "adhd.collect/1", "collector": {"name": "Collect-ADHD.ps1", "version": "0.1.2"}, "bundle": name,
        "startedUtc": ago(0.01), "finishedUtc": AS_OF.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "runContext": {"parameters": {"include": modules or []}},
        "scope": scope or {}, "pseudonymization": {"enabled": True, "keyId": key_id}, "datasets": entries, "warnings": [],
    }
    (out / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
    return out


# =============================================================================================
def _ad_common(vulnerable: bool) -> dict[str, Any]:
    v = vulnerable
    users = [
        user(500, "Administrator", flags=("NORMAL_ACCOUNT", "NOT_DELEGATED"), adminCount=1, logon=2),
        user(502, "krbtgt", enabled=False, pwd=400 if v else 60, logon=None, adminCount=1),
        user(501, "Guest", enabled=v, logon=None, pwd=None),
        user(1101, "u-da1",
             flags=("NORMAL_ACCOUNT", "DONT_EXPIRE_PASSWORD") if v else ("NORMAL_ACCOUNT", "NOT_DELEGATED"),
             spn=("MSSQLSvc/sql01.corp.local:1433",) if v else (), logon=200 if v else 3, adminCount=1,
             keyCredentialLinkCount=1 if v else 0),
        user(1103, "u-helpdesk", logon=1),
        user(1105, "u-cloudadmin", logon=1),
        user(1106, "svc-aadc", logon=1, pwd=100, flags=("NORMAL_ACCOUNT", "NOT_DELEGATED"), keyCredentialLinkCount=1 if v else 0),
    ]
    if v:
        users += [
            user(1102, "u-svc", spn=("HTTP/app01.corp.local",), pwd=500,
                 flags=("NORMAL_ACCOUNT", "DONT_REQ_PREAUTH", "PASSWD_NOTREQD", "ENCRYPTED_TEXT_PWD_ALLOWED",
                        "TRUSTED_TO_AUTH_FOR_DELEGATION"),
                 descriptionHasSecretHint=True, sidHistory=["S-1-5-21-99-99-99-512"],
                 allowedToDelegateTo=["cifs/dc01.corp.local"]),
            user(1104, "u-old", logon=300, adminCount=1),
            user(1107, "u-evil", logon=1),
            user(1110, "u-left", enabled=False, logon=200),
        ]
    computers = [
        computer(1000, "DC01", os="Windows Server 2022 Standard", dc=True, laps=False,
                 flags=("SERVER_TRUST_ACCOUNT", "TRUSTED_FOR_DELEGATION"), ou="OU=Domain Controllers",
                 rbcdAllowedPrincipals=[sid(1301)] if v else []),
        computer(1301, "WS01", laps=not v,
                 flags=("WORKSTATION_TRUST_ACCOUNT", "TRUSTED_FOR_DELEGATION") if v else ("WORKSTATION_TRUST_ACCOUNT",)),
        computer(1302, "SRV01", os="Windows Server 2008 R2 Standard" if v else "Windows Server 2022 Standard"),
        computer(1303, "AZUREADSSOACC", os=None, laps=False, pwd=100 if v else 10, logon=None, ou="CN=Computers"),
        computer(1304, "CA01", os="Windows Server 2022 Standard", ou="OU=Workstations" if v else "OU=Tier0 Servers"),
        computer(1305, "CA-AADC", os="Windows Server 2022 Standard", laps=not v, ou="OU=Workstations" if v else "OU=Tier0 Servers"),
    ]
    if v:
        computers.append(computer(1306, "OLD-PC", os="Windows 10 Enterprise", laps=False, logon=400))
    groups = [
        group(sid(512), "Domain Admins", [sid(500), sid(1101)], adminCount=1),
        group(sid(519), "Enterprise Admins", [sid(500)], adminCount=1),
        group(sid(516), "Domain Controllers", []),
        group(sid(513), "Domain Users", []),
        group(sid(515), "Domain Computers", []),
        group(sid(517), "Cert Publishers", [sid(1304)]),
        group(sid(525), "Protected Users", [] if v else [sid(1101)]),
        group(sid(526), "Key Admins", []),
        group(sid(527), "Enterprise Key Admins", []),
        group("S-1-5-32-544", "Administrators", [sid(512), sid(519)], isBuiltin=True),
        group("S-1-5-32-548", "Account Operators", [sid(1103)] if v else [], isBuiltin=True),
        group("S-1-5-32-554", "Pre-Windows 2000 Compatible Access", ["S-1-5-7"] if v else ["S-1-5-11"], isBuiltin=True),
        group(sid(1201), "Helpdesk", [sid(1103)]),
        group(sid(571), "Allowed RODC Password Replication Group", [], descriptionHasSecretHint=True),
        group(sid(572), "Denied RODC Password Replication Group", [], descriptionHasSecretHint=True),
        group(sid(1500), "Exchange Windows Permissions", []),
    ]
    gmsa = [{"objectClass": "msDS-GroupManagedServiceAccount", "sid": sid(1400), "name": "gmsa-sql",
             "samAccountName": "gmsa-sql$", "distinguishedName": f"CN=gmsa-sql,CN=Managed Service Accounts,{DOM_DN}",
             "enabled": True, "uacFlags": ["WORKSTATION_TRUST_ACCOUNT"], "servicePrincipalNames": [],
             "principalsAllowedToRetrievePassword": [sid(513)] if v else [sid(1302)], "pwdLastSet": ago(10)}]
    domain = [{
        "dnsRoot": "corp.local", "netBIOSName": "CORP", "distinguishedName": DOM_DN, "domainSid": DOM, "forest": "corp.local",
        "domainMode": "Windows2012R2Domain" if v else "Windows2016Domain", "machineAccountQuota": 10 if v else 0,
        "dsHeuristics": "0000002" if v else None, "krbtgtPwdLastSet": ago(400 if v else 60),
        "lapsLegacySchema": False, "lapsWindowsSchema": True, "keyCredentialLinkSchema": True,
    }]
    forest = [{"name": "corp.local", "optionalFeatures": [{"name": "Recycle Bin Feature", "enabled": not v}]}]
    policies = [{"kind": "default", "name": "Default Domain Policy", "minPasswordLength": 7 if v else 14,
                 "lockoutThreshold": 0 if v else 10, "complexityEnabled": True, "reversibleEncryptionEnabled": False}]
    trusts = [{"name": "partner.local", "target": "partner.local", "direction": "Bidirectional", "trustType": "Uplevel",
               "trustAttributes": 0 if v else 4, "forestTransitive": False, "intraForest": False,
               "sidFilteringQuarantined": not v, "tgtDelegation": False, "usesAESKeys": True, "usesRC4Encryption": False}]
    ous = [
        {"objectClass": "domainDNS", "name": "corp.local", "distinguishedName": DOM_DN,
         "gpLinks": [{"gpoGuid": GPO_DDP, "enabled": True, "enforced": False, "order": 1}], "blockInheritance": False},
        {"objectClass": "organizationalUnit", "name": "Domain Controllers", "distinguishedName": f"OU=Domain Controllers,{DOM_DN}",
         "gpLinks": [{"gpoGuid": GPO_DDCP, "enabled": True, "enforced": False, "order": 1}], "blockInheritance": False},
        {"objectClass": "organizationalUnit", "name": "Workstations", "distinguishedName": f"OU=Workstations,{DOM_DN}",
         "gpLinks": [], "blockInheritance": False, "descriptionHasSecretHint": False},
        {"objectClass": "organizationalUnit", "name": "Tier0 Servers", "distinguishedName": f"OU=Tier0 Servers,{DOM_DN}",
         "gpLinks": [], "blockInheritance": False, "descriptionHasSecretHint": False},
    ]
    gpos = [{"id": GPO_DDP, "displayName": "Default Domain Policy"},
            {"id": GPO_DDCP, "displayName": "Default Domain Controllers Policy"}]

    root_aces = [
        ace(sid(512), "GenericAll"), ace("S-1-5-18", "GenericAll"),
        ace("S-1-5-9", "ExtendedRight", DCSYNC, "DS-Replication-Get-Changes"),
        ace("S-1-5-32-544", "ExtendedRight", DCSYNC, "DS-Replication-Get-Changes"),
        ace("S-1-5-32-544", "ExtendedRight", DCSYNC_ALL, "DS-Replication-Get-Changes-All"),
        ace(sid(516), "ExtendedRight", DCSYNC_ALL, "DS-Replication-Get-Changes-All"),
        ace(sid(1106), "ExtendedRight", DCSYNC, "DS-Replication-Get-Changes"),
        ace(sid(1106), "ExtendedRight", DCSYNC_ALL, "DS-Replication-Get-Changes-All"),
        ace("S-1-5-32-554", "ReadProperty", inheritance="Descendents", inherited="user"),
        ace(sid(527), "ReadProperty, WriteProperty", "5b47d60f", "msDS-KeyCredentialLink", inheritance="All"),
        ace("S-1-5-11", "ExtendedRight", "ccc2dc7d", "Unexpire-Password"),
    ]
    if v:
        root_aces += [
            ace(sid(1107), "ExtendedRight", DCSYNC, "DS-Replication-Get-Changes"),
            ace(sid(1107), "ExtendedRight", DCSYNC_ALL, "DS-Replication-Get-Changes-All"),
            ace(sid(1500), "WriteDacl"),
            ace(sid(1201), "ExtendedRight", DCSYNC, "DS-Replication-Get-Changes", inheritance="Descendents"),
        ]
    acls = [
        {"distinguishedName": DOM_DN, "objectClass": "domainDNS", "sid": DOM, "reason": "domainRoot",
         "owner": sid(512), "daclProtected": False, "aces": root_aces},
        {"distinguishedName": f"CN=AdminSDHolder,CN=System,{DOM_DN}", "objectClass": "container", "reason": "adminSDHolder",
         "owner": sid(512), "daclProtected": True,
         "aces": [ace(sid(512), "GenericAll"), ace("S-1-1-0", "ExtendedRight", "ab721a53", "User-Change-Password")]
         + ([ace(sid(1104), "WriteDacl")] if v else [])},
        {"distinguishedName": f"CN=Domain Admins,CN=Users,{DOM_DN}", "objectClass": "group", "sid": sid(512), "reason": "adminCount",
         "owner": sid(512), "daclProtected": True,
         "aces": [ace(sid(512), "GenericAll")] + ([ace(sid(1201), "GenericAll")] if v else [])},
        {"distinguishedName": f"CN=u-da1,CN=Users,{DOM_DN}", "objectClass": "user", "sid": sid(1101), "reason": "adminCount",
         "owner": sid(512) if v else sid(512), "daclProtected": True,
         "aces": [ace("S-1-5-10", "ReadProperty, WriteProperty", "77b5b886", "Personal-Information")]
         + ([ace(sid(1201), "ExtendedRight", "00299570", "User-Force-Change-Password")] if v else [])},
        {"distinguishedName": f"OU=Domain Controllers,{DOM_DN}", "objectClass": "organizationalUnit", "reason": "ou",
         "owner": sid(512), "daclProtected": False,
         "aces": [ace("S-1-5-11", "ReadProperty")] + ([ace(sid(1201), "WriteProperty", "f30e3bbe", "gPLink")] if v else [])},
        {"distinguishedName": f"OU=Workstations,{DOM_DN}", "objectClass": "organizationalUnit", "reason": "ou",
         "owner": sid(512), "daclProtected": False, "aces": [ace(sid(1201), "GenericAll", inheritance="All")]},
        {"distinguishedName": f"CN={{{GPO_DDCP.upper()}}},CN=Policies,CN=System,{DOM_DN}", "objectClass": "groupPolicyContainer",
         "reason": "gpo", "owner": sid(512), "daclProtected": False,
         "aces": [ace(sid(512), "GenericAll"), ace("S-1-5-11", "ReadProperty, ExtendedRight", "edacfd8f", "Apply-Group-Policy"),
                  ace("S-1-3-0", "GenericAll", inheritance="Descendents")]
         + ([ace(sid(1201), "GenericWrite")] if v else [])},
        {"distinguishedName": f"CN=DC01,OU=Domain Controllers,{DOM_DN}", "objectClass": "computer", "sid": sid(1000),
         "reason": "domainController", "owner": sid(512), "daclProtected": False,
         "aces": [ace(sid(526), "ReadProperty, WriteProperty", "5b47d60f", "msDS-KeyCredentialLink")]},
        {"distinguishedName": f"CN=svc-aadc,CN=Users,{DOM_DN}", "objectClass": "user", "sid": sid(1106), "reason": "syncInfra",
         "owner": sid(512), "daclProtected": False, "aces": []},
    ]
    templates = [
        {"name": "User", "displayName": "User", "distinguishedName": f"CN=User,CN=Certificate Templates,{PKS}", "published": True,
         "enrolleeSuppliesSubject": False, "managerApproval": False, "authorizedSignaturesRequired": 0,
         "extendedKeyUsage": ["1.3.6.1.5.5.7.3.2"], "applicationPolicies": [], "clientAuthCapable": True,
         "enrollmentAgent": False, "noSecurityExtension": False, "owner": sid(519),
         "aces": [ace(sid(513), "ReadProperty, ExtendedRight", ENROLL, "Certificate-Enrollment"), ace(sid(519), "GenericAll")]},
    ]
    if v:
        templates += [
            {"name": "ESC1", "displayName": "ESC1", "distinguishedName": f"CN=ESC1,CN=Certificate Templates,{PKS}", "published": True,
             "enrolleeSuppliesSubject": True, "managerApproval": False, "authorizedSignaturesRequired": 0,
             "extendedKeyUsage": ["1.3.6.1.5.5.7.3.2"], "applicationPolicies": [], "clientAuthCapable": True, "noSecurityExtension": False,
             "owner": sid(519), "aces": [ace(sid(513), "ExtendedRight", ENROLL, "Certificate-Enrollment")]},
            {"name": "ESC2", "displayName": "ESC2", "distinguishedName": f"CN=ESC2,CN=Certificate Templates,{PKS}", "published": True,
             "enrolleeSuppliesSubject": False, "managerApproval": False, "authorizedSignaturesRequired": 0,
             "extendedKeyUsage": [], "applicationPolicies": [], "clientAuthCapable": True, "noSecurityExtension": False,
             "owner": sid(519), "aces": [ace(sid(1201), "ExtendedRight", ENROLL, "Certificate-Enrollment")]},
            {"name": "ESC3", "displayName": "ESC3", "distinguishedName": f"CN=ESC3,CN=Certificate Templates,{PKS}", "published": True,
             "enrolleeSuppliesSubject": False, "managerApproval": False, "authorizedSignaturesRequired": 0,
             "extendedKeyUsage": ["1.3.6.1.4.1.311.20.2.1"], "applicationPolicies": [], "clientAuthCapable": False,
             "noSecurityExtension": False, "owner": sid(519),
             "aces": [ace(sid(1102), "ExtendedRight", ENROLL, "Certificate-Enrollment")]},
            {"name": "ESC4", "displayName": "ESC4", "distinguishedName": f"CN=ESC4,CN=Certificate Templates,{PKS}", "published": True,
             "enrolleeSuppliesSubject": False, "managerApproval": True, "authorizedSignaturesRequired": 0,
             "extendedKeyUsage": ["1.3.6.1.5.5.7.3.1"], "applicationPolicies": [], "clientAuthCapable": False,
             "noSecurityExtension": False, "owner": sid(519), "aces": [ace("S-1-5-11", "GenericAll")]},
            {"name": "OrphanACL", "displayName": "OrphanACL", "distinguishedName": f"CN=OrphanACL,CN=Certificate Templates,{PKS}",
             "published": False, "enrolleeSuppliesSubject": False, "managerApproval": True, "authorizedSignaturesRequired": 0,
             "extendedKeyUsage": ["1.3.6.1.5.5.7.3.1"], "applicationPolicies": [], "clientAuthCapable": False,
             "noSecurityExtension": False, "owner": sid(519), "aces": [ace(sid(2104), "GenericAll")]},
            {"name": "ESC9", "displayName": "ESC9", "distinguishedName": f"CN=ESC9,CN=Certificate Templates,{PKS}", "published": True,
             "enrolleeSuppliesSubject": False, "managerApproval": False, "authorizedSignaturesRequired": 0,
             "extendedKeyUsage": ["1.3.6.1.5.5.7.3.2"], "applicationPolicies": [], "clientAuthCapable": True,
             "noSecurityExtension": True, "owner": sid(519),
             "aces": [ace(sid(1201), "ExtendedRight", ENROLL, "Certificate-Enrollment")]},
        ]
    cas = [{"name": "CORP-CA", "displayName": "CORP-CA", "dnsHostName": "ca01.corp.local",
            "distinguishedName": f"CN=CORP-CA,CN=Enrollment Services,{PKS}",
            "certificateTemplates": [t["name"] for t in templates if t["published"]], "owner": sid(519),
            "aces": [ace(sid(1304), "GenericAll")]}]
    containers = [
        {"name": "NTAuthCertificates", "distinguishedName": f"CN=NTAuthCertificates,{PKS}", "objectClass": "certificationAuthority",
         "owner": sid(519), "aces": [ace(sid(519), "GenericAll")] + ([ace(sid(1201), "WriteDacl")] if v else [])},
        {"name": "AIA", "distinguishedName": f"CN=AIA,{PKS}", "objectClass": "container", "owner": sid(519),
         "aces": [ace(sid(517), "GenericAll", inheritance="All")]},
    ]
    data = {
        "ad_forest": forest, "ad_domain": domain, "ad_password_policies": policies, "ad_trusts": trusts,
        "ad_domain_controllers": [{"name": "DC01", "hostName": "dc01.corp.local"}], "ad_ous": ous,
        "ad_users": users, "ad_computers": computers, "ad_service_accounts": gmsa, "ad_groups": groups,
        "ad_guid_map": [], "ad_acls": acls, "ad_gpos": gpos,
        "gpo_gpp_cpassword": [{"gpoGuid": GPO_DDP, "scope": "Machine", "file": "Groups.xml", "cpasswordPresent": True,
                               "occurrences": 1}] if v else [],
        "adcs_containers": containers, "adcs_cas": cas, "adcs_templates": templates,
    }
    return data


def _entra(vulnerable: bool) -> dict[str, Any]:
    v = vulnerable

    def eu(oid, upn, **kw):
        row = {"id": oid, "userPrincipalName": upn, "displayName": upn.split("@")[0], "accountEnabled": True, "userType": "Member",
               "onPremisesSyncEnabled": None, "onPremisesSecurityIdentifier": None, "createdDateTime": ago(500),
               "signInActivity": {"lastSignInDateTime": ago(2)}}
        row.update(kw)
        return row

    users = [
        eu("e-ga1", "ga1@corp.onmicrosoft.com"),
        eu("e-ga2", "ga2@corp.onmicrosoft.com"),
        eu("e-user", "user@corp.com", onPremisesSyncEnabled=True, onPremisesSecurityIdentifier=sid(1103)),
        eu("e-da1", "u-da1@corp.com", onPremisesSyncEnabled=v or None, onPremisesSecurityIdentifier=sid(1101) if v else None),
        eu("e-cloudadmin", "u-cloudadmin@corp.com", onPremisesSyncEnabled=True, onPremisesSecurityIdentifier=sid(1105)),
        eu("e-x1", "x1@corp.com"), eu("e-x2", "x2@corp.com"), eu("e-x3", "x3@corp.com"),
        eu("e-sync", "Sync_AADC01_1@corp.onmicrosoft.com"),
    ]
    if v:
        users += [
            eu("e-guestadmin", "partner_x.com#EXT#@corp.onmicrosoft.com", userType="Guest"),
            eu("e-staleadmin", "stale@corp.onmicrosoft.com", signInActivity={"lastSignInDateTime": ago(200)}),
            eu("e-staleguest", "g_y.com#EXT#@corp.onmicrosoft.com", userType="Guest",
               signInActivity={"lastSignInDateTime": ago(300)}),
            eu("e-left", "u-left@corp.com", onPremisesSyncEnabled=True, onPremisesSecurityIdentifier=sid(1110),
               onPremisesLastSyncDateTime=ago(200), signInActivity={"lastSignInDateTime": ago(3)}),
        ]
    reg = [{"id": u["id"], "userPrincipalName": u["userPrincipalName"], "isMfaRegistered": True, "methodsRegistered": ["fido2"]}
           for u in users]
    if v:
        for r in reg:
            if r["id"] in ("e-cloudadmin", "e-guestadmin"):
                r["isMfaRegistered"] = False
    groups = [
        {"id": "g-priv", "displayName": "PRA Group", "isAssignableToRole": True, "securityEnabled": True},
        {"id": "g-excl", "displayName": "CA Exclusions", "isAssignableToRole": False, "securityEnabled": True},
    ]
    memberships = [
        {"groupId": "g-priv", "isAssignableToRole": True, "transitiveMembers": [{"id": "e-ga2", "type": "user"}],
         "owners": [{"id": "e-user", "type": "user"}] if v else [{"id": "e-ga1", "type": "user"}]},
        {"groupId": "g-excl", "isAssignableToRole": False,
         "transitiveMembers": [{"id": x, "type": "user"} for x in (["e-x1", "e-x2", "e-x3"] if v else ["e-x1"])], "owners": []},
    ]
    role_defs = [{"id": GA, "displayName": "Global Administrator", "isBuiltIn": True},
                 {"id": PRA, "displayName": "Privileged Role Administrator", "isBuiltIn": True},
                 {"id": SEC_ADMIN, "displayName": "Security Administrator", "isBuiltIn": True},
                 {"id": APP_ADMIN, "displayName": "Application Administrator", "isBuiltIn": True},
                 {"id": USER_ADMIN, "displayName": "User Administrator", "isBuiltIn": True},
                 {"id": "d29b2b05-8046-44ba-8758-1e26182fcf32", "displayName": "Directory Synchronization Accounts"}]
    assignments = [
        {"id": "ra1", "principalId": "e-ga1", "roleDefinitionId": GA, "directoryScopeId": "/"},
        {"id": "ra2", "principalId": "e-ga2", "roleDefinitionId": GA, "directoryScopeId": "/"},
        {"id": "ra3", "principalId": "g-priv", "roleDefinitionId": PRA, "directoryScopeId": "/"},
        {"id": "ra4", "principalId": "e-sync", "roleDefinitionId": "d29b2b05-8046-44ba-8758-1e26182fcf32", "directoryScopeId": "/"},
    ]
    if v:
        assignments += [
            {"id": "ra5", "principalId": "e-cloudadmin", "roleDefinitionId": GA, "directoryScopeId": "/"},
            {"id": "ra6", "principalId": "e-guestadmin", "roleDefinitionId": USER_ADMIN, "directoryScopeId": "/"},
            {"id": "ra7", "principalId": "sp-role", "roleDefinitionId": APP_ADMIN, "directoryScopeId": "/"},
        ]
    eligibility = [{"id": "el1", "principalId": "e-staleadmin", "roleDefinitionId": SEC_ADMIN, "directoryScopeId": "/"}] if v else []
    pim_assign = [{"principalId": "e-ga1", "roleDefinitionId": GA, "assignmentType": "Assigned",
                   "scheduleInfo": {"expiration": {"type": "noExpiration"}}}] if v else \
        [{"principalId": "e-ga1", "roleDefinitionId": GA, "assignmentType": "Assigned",
          "scheduleInfo": {"expiration": {"type": "afterDateTime", "endDateTime": ahead(30)}}}]
    sps = [
        {"id": "sp-graph", "appId": "00000003-0000-0000-c000-000000000000", "displayName": "Microsoft Graph",
         "appOwnerOrganizationId": "f8cdef31-a31e-4b4a-93e4-5f571e91255a", "servicePrincipalType": "Application"},
        {"id": "sp-app", "appId": "app-1", "displayName": "HR Sync", "appOwnerOrganizationId": TENANT,
         "servicePrincipalType": "Application", "passwordCredentials": []},
        {"id": "sp-app2", "appId": "app-2", "displayName": "Legacy Tool", "appOwnerOrganizationId": TENANT,
         "servicePrincipalType": "Application", "preferredSingleSignOnMode": None,
         "passwordCredentials": [{"keyId": "spk1", "endDateTime": ahead(300)}] if v else []},
        {"id": "sp-role", "appId": "app-3", "displayName": "Automation", "appOwnerOrganizationId": TENANT,
         "servicePrincipalType": "Application"},
        {"id": "sp-photos", "appId": "ms-photos", "displayName": "Microsoft Photos",
         "appOwnerOrganizationId": "f8cdef31-a31e-4b4a-93e4-5f571e91255a", "servicePrincipalType": "Application"},
        {"id": "sp-p2p", "appId": "p2p", "displayName": "P2P Server", "appOwnerOrganizationId": TENANT,
         "servicePrincipalType": "Application", "passwordCredentials": [{"keyId": "p1", "endDateTime": ahead(200)}]},
    ]
    apps = [
        {"id": "a-1", "appId": "app-1", "displayName": "HR Sync",
         "passwordCredentials": [{"keyId": "k1", "startDateTime": ago(10), "endDateTime": ahead(1090 if v else 170)}],
         "keyCredentials": [{"keyId": "k2", "startDateTime": ago(800), "endDateTime": ago(5)}] if v else []},
    ]
    app_owners = [{"applicationId": "a-1", "appId": "app-1", "owners": [{"id": "e-user", "type": "user"}] if v else []}]
    catalog = [{"id": "sp-graph", "appId": "00000003-0000-0000-c000-000000000000", "displayName": "Microsoft Graph",
                "appRoles": [{"id": "role-rmrw", "value": "RoleManagement.ReadWrite.Directory"},
                             {"id": "role-mailrw", "value": "Mail.ReadWrite"},
                             {"id": "role-userread", "value": "User.Read.All"}], "scopes": []}]
    ara = [{"id": "x1", "appRoleId": "role-userread", "principalId": "sp-app", "resourceId": "sp-graph"}]
    if v:
        ara += [{"id": "x2", "appRoleId": "role-rmrw", "principalId": "sp-app", "resourceId": "sp-graph"},
                {"id": "x3", "appRoleId": "role-mailrw", "principalId": "sp-app2", "resourceId": "sp-graph"}]
    grants = [{"clientId": "sp-app", "consentType": "AllPrincipals", "resourceId": "sp-graph",
               "scope": "User.Read Mail.ReadWrite" if v else "User.Read openid"}]
    if v:
        grants.append({"clientId": "sp-photos", "consentType": "AllPrincipals", "resourceId": "sp-graph",
                       "scope": "Files.ReadWrite.All"})
    authz = [{"id": "authorizationPolicy", "allowInvitesFrom": "everyone" if v else "adminsAndGuestInviters",
              "guestUserRoleId": "a0b1b346-4d3e-4e8b-98f8-753987be4970" if v else "2af84b1e-32c8-42b7-82bc-daa82404023b",
              "defaultUserRolePermissions": {"allowedToCreateApps": v},
              "permissionGrantPolicyIdsAssignedToDefaultUserRole":
                  ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"] if v else []}]
    ca = [
        {"id": "ca-admin", "displayName": "MFA for admins", "state": "enabled",
         "conditions": {"users": {"includeRoles": [GA], "excludeGroups": ["g-excl"]},
                        "applications": {"includeApplications": ["All"]}, "clientAppTypes": ["all"]},
         "grantControls": {"operator": "OR", "builtInControls": ["mfa"]}},
        {"id": "ca-report", "displayName": "Block risky (report)", "state": "enabledForReportingButNotEnforced",
         "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]}},
         "grantControls": {"builtInControls": ["block"]}},
    ]
    if not v:
        ca += [
            {"id": "ca-all", "displayName": "MFA for all", "state": "enabled",
             "conditions": {"users": {"includeUsers": ["All"], "excludeGroups": ["g-excl"]},
                            "applications": {"includeApplications": ["All"]}},
             "grantControls": {"builtInControls": ["mfa"]}},
            {"id": "ca-legacy", "displayName": "Block legacy auth", "state": "enabled",
             "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]},
                            "clientAppTypes": ["exchangeActiveSync", "other"]},
             "grantControls": {"builtInControls": ["block"]}},
        ]
    risky = [{"id": "e-user", "userPrincipalName": "user@corp.com", "riskLevel": "high", "riskState": "atRisk"}] if v else \
        [{"id": "e-user", "userPrincipalName": "user@corp.com", "riskLevel": "high", "riskState": "remediated"}]
    domains = [{"id": "corp.com", "authenticationType": "Federated" if v else "Managed"},
               {"id": "corp.onmicrosoft.com", "authenticationType": "Managed"}]
    return {
        "entra_organization": [{"id": TENANT, "displayName": "Corp", "onPremisesSyncEnabled": True,
                                "onPremisesLastSyncDateTime": ago(0.02)}], "entra_domains": domains, "entra_users": users,
        "entra_groups": groups, "entra_role_definitions": role_defs, "entra_role_assignments": assignments,
        "entra_pim_eligibility": eligibility, "entra_pim_assignments": pim_assign, "entra_admin_units": [],
        "entra_admin_unit_roles": [], "entra_ca_policies": ca, "entra_named_locations": [],
        "entra_authorization_policy": authz, "entra_security_defaults": [{"id": "sd", "isEnabled": False}],
        "entra_auth_methods_policy": [{"id": "amp"}], "entra_user_registration": reg, "entra_devices": [],
        "entra_group_memberships": memberships, "entra_applications": apps, "entra_application_owners": app_owners,
        "entra_service_principals": sps, "entra_sp_owners": [], "entra_app_role_assignments": ara,
        "entra_oauth2_grants": grants, "entra_permission_catalog": catalog, "entra_risky_users": risky,
    }


def _aadc(vulnerable: bool) -> dict[str, Any]:
    admins = [{"name": "CORP\\Domain Admins", "sid": sid(512), "objectClass": "Group", "principalSource": "ActiveDirectory"},
              {"name": "CA-AADC\\Administrator", "sid": "S-1-5-21-777-888-999-500", "objectClass": "User", "principalSource": "Local"}]
    if vulnerable:
        admins.append({"name": "CORP\\u-svc", "sid": sid(1102), "objectClass": "User", "principalSource": "ActiveDirectory"})
    return {
        "entraconnect_server": [{"computerName": "CA-AADC", "products": [{"product": "Microsoft Entra Connect Sync", "version": "2.4"}],
                                 "adsyncServiceAccount": "NT SERVICE\\ADSync", "localAdministrators": admins}],
        "entraconnect_scheduler": [{"SyncCycleEnabled": True, "StagingModeEnabled": False}],
        "entraconnect_features": [{"PasswordHashSync": True, "UserWriteback": False}],
        "entraconnect_connectors": [{"name": "corp.local", "type": "AD",
                                     "connectivityParameters": {"forest-name": "corp.local", "forest-login-user": "svc-aadc"},
                                     "creationTime": ago(900), "passwordHashSyncEnabled": True}],
    }


def make_round(root: Path, vulnerable: bool, *, key_id: str = "testkey1") -> list[Path]:
    scope = {"adDomain": "corp.local", "adDomainSid": DOM, "entraTenantId": TENANT}
    main = dict(_ad_common(vulnerable))
    main.update(_entra(vulnerable))
    b1 = write_bundle(root, "ADHD-Collect-Test", main, key_id=key_id, modules=["AD", "ADACL", "GPO", "ADCS", "Entra"], scope=scope)
    b2 = write_bundle(root, "ADHD-Collect-Test-AADC", _aadc(vulnerable), key_id=key_id, modules=["EntraConnect"])
    return [b1, b2]
