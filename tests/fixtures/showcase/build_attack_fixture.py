"""Build the deterministic, test-only Enterprise ATT&CK showcase bundle."""

import json
from pathlib import Path
from uuid import UUID, uuid5

ROOT = Path(__file__).parent
OUTPUT = ROOT / "attack" / "enterprise-attack-showcase.json"
NAMESPACE = UUID("00000000-0000-4000-8000-000000009999")
STAMP = "2026-01-01T00:00:00.000Z"

TECHNIQUES = [
    ("T1566.001", "Spearphishing Attachment", "initial-access", True),
    ("T1566.002", "Spearphishing Link", "initial-access", True),
    ("T1190", "Exploit Public-Facing Application", "initial-access", False),
    ("T1059.001", "PowerShell", "execution", True),
    ("T1059.003", "Windows Command Shell", "execution", True),
    ("T1105", "Ingress Tool Transfer", "command-and-control", False),
    ("T1071.001", "Web Protocols", "command-and-control", True),
    ("T1071.004", "DNS", "command-and-control", True),
    ("T1027", "Obfuscated Files", "defense-evasion", False),
    ("T1003.001", "LSASS Memory", "credential-access", True),
    ("T1082", "System Information Discovery", "discovery", False),
    ("T1018", "Remote System Discovery", "discovery", False),
    ("T1021.001", "Remote Desktop Protocol", "lateral-movement", True),
    ("T1041", "Exfiltration Over C2", "exfiltration", False),
    ("T1053.005", "Scheduled Task", "persistence", True),
    ("T1547.001", "Registry Run Keys", "persistence", True),
    ("T1110", "Brute Force", "credential-access", False),
    ("T1078", "Valid Accounts", "privilege-escalation", False),
]
GROUP_NAMES = [
    ("G0016", "APT29", ["Cozy Bear", "The Dukes", "Midnight Blizzard"]),
    ("G0018", "APT28", ["Fancy Bear"]),
    ("G0046", "FIN7", []),
    ("G0032", "Lazarus Group", ["HIDDEN COBRA"]),
    ("G0010", "Turla", []),
    ("G0034", "Sandworm Team", []),
    ("G0047", "menuPass", []),
    ("G0094", "Kimsuky", []),
    ("G0127", "Mustang Panda", []),
    ("G0049", "OilRig", []),
    ("G9001", "SHOWCASE Lynx", ["Lynx Fixture"]),
    ("G9002", "SHOWCASE Ember", []),
]
SOFTWARE = [
    "PowerShell",
    "Mimikatz",
    "PsExec",
    "Rclone",
    "SHOWCASE SimLoader",
    "SHOWCASE BeaconLite",
    "SHOWCASE RemoteAdminX",
    "SHOWCASE WebDrop",
    "SHOWCASE TunnelProxy",
    "SHOWCASE CredentialDumpX",
]
MITIGATIONS = [
    "Restrict Script Execution",
    "Harden Remote Access",
    "Patch Public-Facing Services",
    "Filter Outbound Traffic",
    "Protect Credential Material",
    "Restrict Administrative Tools",
    "Application Allowlisting",
    "Monitor Email Attachments",
    "Limit Remote Services",
    "Harden Authentication",
    "Network Segmentation",
    "Control Software Execution",
]
DATA_SOURCES = [
    "Process",
    "Network Traffic",
    "File",
    "Email",
    "Authentication",
    "Windows Registry",
    "Command",
    "Script",
]
DATA_COMPONENTS = [
    ("Process Creation", "Process"),
    ("Process Access", "Process"),
    ("Network Traffic Flow", "Network Traffic"),
    ("Network Traffic Content", "Network Traffic"),
    ("Network Connection Creation", "Network Traffic"),
    ("File Creation", "File"),
    ("File Modification", "File"),
    ("Email Attachment", "Email"),
    ("Logon Session Creation", "Authentication"),
    ("Registry Key Modification", "Windows Registry"),
    ("Command Execution", "Command"),
    ("Script Execution", "Script"),
    ("Authentication Attempt", "Authentication"),
    ("File Access", "File"),
]
TACTICS = {
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
}


def sid(kind: str, value: str) -> str:
    value_uuid = uuid5(NAMESPACE, f"{kind}:{value}")
    raw = value_uuid.int
    raw = (raw & ~(0xF << 76)) | (0x4 << 76)
    raw = (raw & ~(0x3 << 62)) | (0x2 << 62)
    return f"{kind}--{UUID(int=raw)}"


def base(kind: str, key: str, name: str) -> dict[str, object]:
    return {
        "type": kind,
        "spec_version": "2.0",
        "id": sid(kind, key),
        "created": STAMP,
        "modified": STAMP,
        "name": name,
        "description": f"SHOWCASE simulated fixture object for {name}.",
        "x_mitre_domains": ["enterprise-attack"],
        "revoked": False,
        "x_mitre_deprecated": False,
    }


def ref(external_id: str) -> list[dict[str, str]]:
    return [
        {
            "source_name": "mitre-attack",
            "external_id": external_id,
            "url": f"https://example.invalid/showcase/{external_id}",
        }
    ]


def relationship(source: str, target: str, relationship_type: str = "uses") -> dict[str, object]:
    return {
        "type": "relationship",
        "spec_version": "2.0",
        "id": sid("relationship", f"{source}:{relationship_type}:{target}"),
        "created": STAMP,
        "modified": STAMP,
        "relationship_type": relationship_type,
        "source_ref": source,
        "target_ref": target,
    }


def build() -> None:
    objects: list[dict[str, object]] = []
    for shortname, name in TACTICS.items():
        tactic = base("x-mitre-tactic", f"TA-{shortname}", name)
        tactic.update({"x_mitre_shortname": shortname, "external_references": ref(f"TA-{shortname}")})
        objects.append(tactic)
    technique_ids: dict[str, str] = {}
    for external_id, name, tactic, subtechnique in TECHNIQUES:
        item = base("attack-pattern", external_id, name)
        item.update(
            {
                "external_references": ref(external_id),
                "x_mitre_platforms": ["Windows", "Linux"],
                "x_mitre_is_subtechnique": subtechnique,
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": tactic}],
                "x_mitre_version": "showcase-1.0",
            }
        )
        objects.append(item)
        technique_ids[external_id] = str(item["id"])
    group_ids: list[str] = []
    for index, (external_id, name, aliases) in enumerate(GROUP_NAMES):
        item = base("intrusion-set", external_id, name)
        item.update({"external_references": ref(external_id), "aliases": aliases})
        objects.append(item)
        group_ids.append(str(item["id"]))
        count = 12 - min(index, 8)
        start = index % len(TECHNIQUES)
        for entry in (TECHNIQUES * 2)[start : start + count]:
            objects.append(relationship(str(item["id"]), technique_ids[entry[0]]))
    software_ids: list[str] = []
    for index, name in enumerate(SOFTWARE, 1):
        item = base("tool" if index < 5 else "malware", f"S9{index:03d}", name)
        item.update(
            {
                "external_references": ref(f"S9{index:03d}"),
                "x_mitre_platforms": ["Windows"],
                "labels": ["showcase-fixture"],
            }
        )
        objects.append(item)
        software_ids.append(str(item["id"]))
        for entry in TECHNIQUES[index % 8 : index % 8 + 3]:
            objects.append(relationship(str(item["id"]), technique_ids[entry[0]]))
    for index, group_id in enumerate(group_ids):
        for software_id in software_ids[index % 5 : index % 5 + 2]:
            objects.append(relationship(group_id, software_id))
    mitigation_ids: list[str] = []
    noisy_description = (
        "SHOWCASE deterministic mitigation guidance. "
        "[Reference](https://example.invalid) <code>example</code> (Citation: SHOWCASE Fixture)"
    )
    for index, name in enumerate(MITIGATIONS, 1):
        mitigation = base("course-of-action", f"M9{index:03d}", name)
        mitigation.update(
            {
                "external_references": ref(f"M9{index:03d}"),
                "description": noisy_description if index % 3 == 0 else f"SHOWCASE deterministic guidance for {name}.",
            }
        )
        objects.append(mitigation)
        mitigation_ids.append(str(mitigation["id"]))
    mitigation_map = {
        "T1059.001": (0, 5, 6, 11),
        "T1190": (2, 6, 10),
        "T1003.001": (4, 5, 9),
        "T1021.001": (1, 8, 10),
        "T1071.001": (3, 9, 10),
        "T1566.001": (7, 9),
        "T1566.002": (7,),
        "T1059.003": (0, 5),
        "T1105": (3,),
        "T1027": (6, 11),
        "T1053.005": (5,),
    }
    for technique_id, mitigation_indexes in mitigation_map.items():
        for index in mitigation_indexes:
            objects.append(relationship(mitigation_ids[index], technique_ids[technique_id], "mitigates"))
    data_source_ids: dict[str, str] = {}
    for index, name in enumerate(DATA_SOURCES, 1):
        source = base("x-mitre-data-source", f"DS9{index:02d}", name)
        source.update({"x_mitre_platforms": ["Windows", "Linux"]})
        objects.append(source)
        data_source_ids[name] = str(source["id"])
    component_ids: list[str] = []
    for index, (name, source_name) in enumerate(DATA_COMPONENTS, 1):
        component = base("x-mitre-data-component", f"DC9{index:02d}", name)
        component.update({"x_mitre_data_source_ref": data_source_ids[source_name]})
        objects.append(component)
        component_ids.append(str(component["id"]))
    detection_map = {
        "T1059.001": (0, 10, 11),
        "T1071.001": (2, 3, 4),
        "T1003.001": (1, 13),
        "T1190": (2, 4),
        "T1082": (0,),
        "T1566.001": (5, 7),
        "T1566.002": (3, 7),
        "T1059.003": (0, 10),
        "T1105": (4, 5),
        "T1027": (5, 6),
        "T1021.001": (4, 8),
        "T1053.005": (0, 11),
        "T1547.001": (6, 9),
        "T1110": (8, 12),
    }
    for technique_id, component_indexes in detection_map.items():
        for index in component_indexes:
            objects.append(relationship(component_ids[index], technique_ids[technique_id], "detects"))
    for index in range(4):
        campaign_id = f"C9{index + 1:03d}"
        campaign = base("campaign", campaign_id, f"SHOWCASE Campaign {index + 1}")
        campaign.update(
            {
                "external_references": ref(campaign_id),
                "first_seen": f"202{index}-01-01T00:00:00Z",
                "last_seen": f"202{index}-12-01T00:00:00Z",
            }
        )
        objects.append(campaign)
        objects.append(relationship(str(campaign["id"]), group_ids[index], "attributed-to"))
        objects.append(relationship(str(campaign["id"]), technique_ids[TECHNIQUES[index][0]]))
        objects.append(relationship(str(campaign["id"]), software_ids[index]))
    bundle = {
        "type": "bundle",
        "id": sid("bundle", "showcase"),
        "spec_version": "2.0",
        "x_mitre_version": "showcase-1.0",
        "objects": sorted(objects, key=lambda item: (str(item["type"]), str(item["id"]))),
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    build()
