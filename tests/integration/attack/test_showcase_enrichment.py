"""Repository-level acceptance tests for the deterministic showcase bundle."""

from pathlib import Path

from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl
from odysafe_threatmap.utils.hashing import compute_sha256

EXPECTED_SHOWCASE_SHA256 = "314ccbfa2bb7b334cdf750fa4ff48932444771d4ab06567a9ec2d39ec75b8ca2"


def test_showcase_bundle_has_varied_mitigation_and_detection_relationships() -> None:
    root = Path(__file__).parents[3]
    path = root / "tests/fixtures/showcase/attack/enterprise-attack-showcase.json"
    repository = AttackRepositoryImpl(path)
    techniques = repository.get_techniques()

    mitigation_counts = [len(item.mitigations) for item in techniques]
    detection_counts = [len(item.data_components) for item in techniques]

    assert max(mitigation_counts) >= 3
    assert 1 in mitigation_counts
    assert 0 in mitigation_counts
    assert max(detection_counts) >= 2
    assert 1 in detection_counts
    assert 0 in detection_counts
    assert {component.data_source_name for item in techniques for component in item.data_components} >= {
        "Process",
        "Network Traffic",
        "Email",
    }


def test_showcase_bundle_has_stable_generated_hash() -> None:
    root = Path(__file__).parents[3]
    path = root / "tests/fixtures/showcase/attack/enterprise-attack-showcase.json"
    assert compute_sha256(path) == EXPECTED_SHOWCASE_SHA256
