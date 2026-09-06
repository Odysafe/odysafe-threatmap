"""Capability-driven ATT&CK compatibility tests using compact STIX 2.0 fixtures."""

import json
import os
from pathlib import Path

import pytest

from odysafe_threatmap.domain.exceptions import AttackDataInvalidError
from odysafe_threatmap.infrastructure.attack.capabilities import (
    CompatibilityState,
    detect_bundle_capabilities,
)
from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl

FIXTURES = Path(__file__).parents[2] / "fixtures" / "attack"


def test_historical_stix20_uses_legacy_detection_route() -> None:
    repository = AttackRepositoryImpl(FIXTURES / "enterprise-attack-legacy-test.json")
    profile = repository.get_capabilities()
    technique = repository.get_technique("T9000")

    assert profile.compatibility is CompatibilityState.SUPPORTED
    assert profile.detection_route == "legacy-data-component"
    assert profile.data_sources_legacy
    assert not profile.detection_strategies
    assert technique is not None
    assert [(item.name, item.data_source_name) for item in technique.data_components] == [
        ("Process Creation", "Process")
    ]


def test_current_stix20_uses_strategy_analytics_and_tolerates_future_types() -> None:
    repository = AttackRepositoryImpl(FIXTURES / "enterprise-attack-current-test.json")
    profile = repository.get_capabilities()
    technique = repository.get_technique("T9000")

    assert profile.detection_route == "detection-strategy"
    assert profile.detection_strategies and profile.analytics and profile.data_components
    assert profile.unknown_object_types == ("x-mitre-something-new",)
    assert technique is not None
    assert technique.tactics == ("Initial Access", "Future Tactic")
    assert {item.analytic_id for item in technique.detection_evidence} == {"AN9000", "AN9001"}
    assert {item.log_source_name for item in technique.detection_evidence} == {
        "EDR Process Events",
        "Script Telemetry",
    }
    assert repository.get_technique("T9998") is None
    assert repository.get_technique("T9997") is None


def test_campaign_inheritance_is_not_merged_into_direct_group_evidence() -> None:
    repository = AttackRepositoryImpl(FIXTURES / "enterprise-attack-current-test.json")

    assert [item.attack_id for item in repository.get_techniques_for_group("G9000")] == ["T9000"]
    assert [item.attack_id for item in repository.get_technique_summaries_for_group("G9000")] == ["T9000"]
    assert repository.get_software_for_group("G9000") == []
    assert repository.get_software_summaries_for_group("G9000") == []
    campaign = repository.get_campaigns_for_group("G9000")[0]
    assert campaign.techniques == ("T9002",)
    assert campaign.software == ("Campaign-only Tool",)


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"hello": "world"}, "not a STIX bundle"),
        ({"type": "bundle", "spec_version": "2.0", "objects": []}, "Enterprise"),
        (
            {
                "type": "bundle",
                "spec_version": "2.1",
                "objects": [
                    {
                        "type": "attack-pattern",
                        "spec_version": "2.1",
                        "x_mitre_domains": ["enterprise-attack"],
                    }
                ],
            },
            "STIX 2.1",
        ),
    ],
)
def test_unsupported_bundle_shapes_fail_with_clear_diagnostics(
    tmp_path: Path, document: dict[str, object], message: str
) -> None:
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(AttackDataInvalidError, match=message):
        detect_bundle_capabilities(path)


@pytest.mark.skipif(not os.getenv("ODYSAFE_REAL_ATTACK_BUNDLE"), reason="real ATT&CK bundle not configured")
def test_optional_real_attack_bundle() -> None:
    path = Path(os.environ["ODYSAFE_REAL_ATTACK_BUNDLE"])
    repository = AttackRepositoryImpl(path)
    profile = repository.get_capabilities()

    assert profile.stix_version == "2.0"
    assert profile.matrices and profile.tactics and profile.techniques and profile.groups
    assert repository.get_techniques()
    assert repository.get_groups()
