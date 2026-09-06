"""Build compact deterministic historical/current ATT&CK compatibility fixtures."""

import json
from pathlib import Path
from uuid import UUID, uuid5

ROOT = Path(__file__).parent
NS = UUID("10000000-0000-4000-8000-000000000016")
STAMP = "2026-01-01T00:00:00.000Z"


def sid(kind: str, key: str) -> str:
    value = uuid5(NS, f"{kind}:{key}")
    raw = (value.int & ~(0xF << 76)) | (0x4 << 76)
    raw = (raw & ~(0x3 << 62)) | (0x2 << 62)
    return f"{kind}--{UUID(int=raw)}"


def obj(kind: str, key: str, name: str, **extra: object) -> dict[str, object]:
    value: dict[str, object] = {
        "type": kind,
        "spec_version": "2.0",
        "id": sid(kind, key),
        "created": STAMP,
        "modified": STAMP,
        "name": name,
        "x_mitre_domains": ["enterprise-attack"],
        "x_mitre_deprecated": False,
    }
    value.update(extra)
    return value


def ref(external_id: str) -> list[dict[str, str]]:
    return [{"source_name": "mitre-attack", "external_id": external_id}]


def rel(key: str, source: str, relation: str, target: str) -> dict[str, object]:
    return {
        "type": "relationship",
        "spec_version": "2.0",
        "id": sid("relationship", key),
        "created": STAMP,
        "modified": STAMP,
        "relationship_type": relation,
        "source_ref": source,
        "target_ref": target,
    }


def common() -> tuple[list[dict[str, object]], dict[str, str]]:
    tactics = [
        obj(
            "x-mitre-tactic",
            "initial",
            "Initial Access",
            x_mitre_shortname="initial-access",
            external_references=ref("TA0001"),
        ),
        obj(
            "x-mitre-tactic",
            "future",
            "Future Tactic",
            x_mitre_shortname="future-tactic",
            external_references=ref("TA9999"),
        ),
    ]
    technique = obj(
        "attack-pattern",
        "technique",
        "Compatibility Technique",
        description="Explicit fixture technique.",
        external_references=ref("T9000"),
        x_mitre_platforms=["Windows"],
        kill_chain_phases=[
            {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"},
            {"kill_chain_name": "mitre-attack", "phase_name": "future-tactic"},
        ],
        x_mitre_attack_spec_version="3.3.0",
        x_mitre_version="4.0",
        x_future_optional_field="tolerated",
    )
    subtechnique = obj(
        "attack-pattern",
        "subtechnique",
        "Compatibility Sub-technique",
        external_references=ref("T9000.001"),
        x_mitre_is_subtechnique=True,
        kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
    )
    group_a = obj(
        "intrusion-set", "group-a", "Compatibility Group A", aliases=["Shared Alias"], external_references=ref("G9000")
    )
    group_b = obj(
        "intrusion-set", "group-b", "Compatibility Group B", aliases=["Shared Alias"], external_references=ref("G9001")
    )
    campaign = obj("campaign", "campaign", "Attributed Compatibility Campaign", external_references=ref("C9000"))
    campaign_only = obj(
        "attack-pattern",
        "campaign-only-technique",
        "Campaign-only Technique",
        external_references=ref("T9002"),
        kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
    )
    campaign_tool = obj(
        "tool",
        "campaign-only-tool",
        "Campaign-only Tool",
        external_references=ref("S9000"),
        labels=["tool"],
        x_mitre_platforms=["Windows"],
    )
    revoked = obj("attack-pattern", "revoked", "Revoked Technique", revoked=True, external_references=ref("T9998"))
    deprecated = obj(
        "attack-pattern",
        "deprecated",
        "Deprecated Technique",
        x_mitre_deprecated=True,
        external_references=ref("T9997"),
    )
    matrix = obj("x-mitre-matrix", "enterprise", "Enterprise ATT&CK", tactic_refs=[item["id"] for item in tactics])
    values = [
        matrix,
        *tactics,
        technique,
        subtechnique,
        group_a,
        group_b,
        campaign,
        campaign_only,
        campaign_tool,
        revoked,
        deprecated,
    ]
    ids = {
        "technique": str(technique["id"]),
        "subtechnique": str(subtechnique["id"]),
        "group": str(group_a["id"]),
        "campaign": str(campaign["id"]),
        "campaign_only": str(campaign_only["id"]),
        "campaign_tool": str(campaign_tool["id"]),
    }
    values.extend(
        [
            rel("group-technique", ids["group"], "uses", ids["technique"]),
            rel("subtechnique", ids["subtechnique"], "subtechnique-of", ids["technique"]),
            rel("campaign-attribution", ids["campaign"], "attributed-to", ids["group"]),
            rel("campaign-technique", ids["campaign"], "uses", ids["campaign_only"]),
            rel("campaign-tool", ids["campaign"], "uses", ids["campaign_tool"]),
        ]
    )
    return values, ids


def legacy() -> dict[str, object]:
    values, ids = common()
    source = obj("x-mitre-data-source", "process", "Process", x_mitre_platforms=["Windows"])
    component = obj("x-mitre-data-component", "creation", "Process Creation", x_mitre_data_source_ref=source["id"])
    values.extend([source, component, rel("legacy-detects", str(component["id"]), "detects", ids["technique"])])
    return {"type": "bundle", "id": sid("bundle", "legacy"), "spec_version": "2.0", "objects": values}


def current() -> dict[str, object]:
    values, ids = common()
    component = obj("x-mitre-data-component", "command", "Command Execution", external_references=ref("DC9000"))
    analytic_a = obj(
        "x-mitre-analytic",
        "analytic-a",
        "Command-line Analytic",
        description="Explicit analytic A.",
        external_references=ref("AN9000"),
        x_mitre_platforms=["Windows"],
        x_mitre_log_source_references=[
            {"x_mitre_data_component_ref": component["id"], "name": "EDR Process Events", "channel": "Security"}
        ],
    )
    analytic_b = obj(
        "x-mitre-analytic",
        "analytic-b",
        "Script Analytic",
        description="Explicit analytic B.",
        external_references=ref("AN9001"),
        x_mitre_platforms=["Windows", "Linux"],
        x_mitre_log_source_references=[
            {"x_mitre_data_component_ref": component["id"], "name": "Script Telemetry", "channel": "Operational"}
        ],
    )
    strategy = obj(
        "x-mitre-detection-strategy",
        "strategy",
        "Command Detection Strategy",
        external_references=ref("DET9000"),
        x_mitre_analytic_refs=[analytic_a["id"], analytic_b["id"]],
    )
    unknown = obj("x-mitre-something-new", "future", "Future Compatible Object", x_new_field={"value": True})
    values.extend(
        [
            component,
            analytic_a,
            analytic_b,
            strategy,
            unknown,
            rel("strategy-detects", str(strategy["id"]), "detects", ids["technique"]),
        ]
    )
    return {"type": "bundle", "id": sid("bundle", "current"), "spec_version": "2.0", "objects": values}


def write(name: str, document: dict[str, object]) -> None:
    (ROOT / name).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    write("enterprise-attack-legacy-test.json", legacy())
    write("enterprise-attack-current-test.json", current())
