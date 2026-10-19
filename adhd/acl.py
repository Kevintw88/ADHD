"""Translate collected ACEs into abusable-right edge kinds.

Only rights that let the holder take control of, or extract secrets from, the target are mapped.
Read rights and narrowly scoped writes (e.g. userCertificate, terminalServer) are ignored, which
keeps the default ACLs Windows ships from producing noise.
"""
from __future__ import annotations

from typing import Any

# Rights that give control over the target (used for Tier0 exposure and, later, path finding).
CONTROL_KINDS = {
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "WriteAllProperties",
    "AllExtendedRights", "ForceChangePassword", "AddMember", "AddSelf", "WriteSPN",
    "AddKeyCredentialLink", "WriteRBCD", "WriteGPLink", "ReadLAPSPassword", "ReadGMSAPassword",
    "WriteGMSAMembership", "DCSync",
}

_WRITE_PROPERTY = {
    "member": "AddMember",
    "serviceprincipalname": "WriteSPN",
    "msds-keycredentiallink": "AddKeyCredentialLink",
    "msds-allowedtoactonbehalfofotheridentity": "WriteRBCD",
    "gplink": "WriteGPLink",
    "msds-groupmsamembership": "WriteGMSAMembership",
}
_EXTENDED = {
    "user-force-change-password": "ForceChangePassword",
    "ds-replication-get-changes": "GetChanges",
    "ds-replication-get-changes-all": "GetChangesAll",
    "certificate-enrollment": "Enroll",
    "certificate-autoenrollment": "Enroll",
}
_LAPS_ATTRS = {"ms-mcs-admpwd", "mslaps-password", "mslaps-encryptedpassword"}


def rights_of(ace: dict[str, Any]) -> set[str]:
    return {r.strip() for r in str(ace.get("rights") or "").split(",") if r.strip()}


def applies_to_self(ace: dict[str, Any]) -> bool:
    """False for inherit-only ACEs (InheritanceType 'Descendents' / 'Children')."""
    return str(ace.get("inheritanceType") or "None") in ("None", "All", "SelfAndChildren")


def classify(ace: dict[str, Any]) -> list[str]:
    """Edge kinds granted by one ACE (Allow only)."""
    if str(ace.get("type")) != "Allow":
        return []
    rights = rights_of(ace)
    ot = str(ace.get("objectTypeName") or "").lower()
    typed = bool(ace.get("objectType"))
    kinds: list[str] = []
    if "GenericAll" in rights:
        kinds.append("GenericAll")
    if "WriteDacl" in rights:
        kinds.append("WriteDacl")
    if "WriteOwner" in rights:
        kinds.append("WriteOwner")
    if "GenericWrite" in rights:
        kinds.append("GenericWrite")
    if "WriteProperty" in rights:
        if not typed:
            kinds.append("WriteAllProperties")
        elif ot in _WRITE_PROPERTY:
            kinds.append(_WRITE_PROPERTY[ot])
    if "Self" in rights and ot in ("member", "self-membership"):
        kinds.append("AddSelf")
    if "ExtendedRight" in rights:
        if not typed:
            kinds.append("AllExtendedRights")
        elif ot in _EXTENDED:
            kinds.append(_EXTENDED[ot])
        elif ot in _LAPS_ATTRS:
            kinds.append("ReadLAPSPassword")
    if "ReadProperty" in rights and ot in _LAPS_ATTRS:
        kinds.append("ReadLAPSPassword")
    return list(dict.fromkeys(kinds))
