"""Unit tests for the Threat Actor Snapshot application service."""

from pathlib import Path

import pytest

from odysafe_threatmap.application.actor_snapshot import ActorSnapshotOptions, ActorSnapshotService
from odysafe_threatmap.domain.exceptions import ActorNotFoundError
from odysafe_threatmap.domain.models import NOT_AVAILABLE
from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl


@pytest.fixture
def service() -> ActorSnapshotService:
    """Create the service backed by the compact local ATT&CK fixture."""
    root = Path(__file__).parents[3]
    return ActorSnapshotService(AttackRepositoryImpl(root / "tests/fixtures/attack/enterprise-attack-test.json"))


@pytest.mark.parametrize("identifier", ["G1001", "example group", "Cozy Bear"])
def test_resolves_actor_by_id_name_and_alias(service: ActorSnapshotService, identifier: str) -> None:
    """Exact identifier resolution follows the documented local policy."""
    result = service.build_snapshot([identifier], ActorSnapshotOptions())
    assert [actor.name for actor in result.actors] == ["Example Group"]
    assert result.actors[0].origin == NOT_AVAILABLE
    assert result.actors[0].first_seen == NOT_AVAILABLE


def test_collects_structured_relationships_and_popularity(service: ActorSnapshotService) -> None:
    """The snapshot uses only relationships from the local bundle."""
    result = service.build_snapshot(["G1001", "G1002"], ActorSnapshotOptions(include_campaigns=True))
    assert {item.attack_id for item in result.techniques} == {"T1059", "T1566.001"}
    assert [item.name for item in result.software] == ["Example Malware"]
    assert [item.name for item in result.campaigns] == ["Example Campaign"]
    assert result.technique_popularity


def test_unknown_actor_has_a_clear_error(service: ActorSnapshotService) -> None:
    """Unknown actor names do not trigger fuzzy identification."""
    with pytest.raises(ActorNotFoundError, match="Actor not found"):
        service.build_snapshot(["unknown actor"], ActorSnapshotOptions())
