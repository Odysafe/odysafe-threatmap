"""Unit tests for local sector profiles."""

from pathlib import Path

import pytest

from odysafe_threatmap.application.sector_profile import SectorProfileOptions, SectorProfileService
from odysafe_threatmap.config.loader import load_actor_metadata
from odysafe_threatmap.domain.exceptions import SectorNotFoundError
from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl


def test_profile_uses_explicit_local_mapping() -> None:
    """Financial data is collected only for mapped groups in the local fixture."""
    root = Path(__file__).parents[3]
    service = SectorProfileService(
        AttackRepositoryImpl(root / "tests/fixtures/attack/enterprise-attack-test.json"),
        load_actor_metadata(root / "src/odysafe_threatmap/config/defaults/actor_metadata.yaml"),
    )
    result = service.build_profile(
        ["financial"],
        SectorProfileOptions(
            tactic_weights={"Initial Access": 4},
            priority_thresholds={"critical_threshold": 150, "high_threshold": 100, "moderate_threshold": 50},
        ),
    )
    assert {actor.attack_id for actor in result.actors} == {"G1001", "G1002"}
    assert result.risk_matrix[0].priority_label == "🟠 High"


def test_unknown_sector_is_rejected() -> None:
    """Sector lookup does not apply fuzzy matching."""
    root = Path(__file__).parents[3]
    service = SectorProfileService(
        AttackRepositoryImpl(root / "tests/fixtures/attack/enterprise-attack-test.json"),
        load_actor_metadata(root / "src/odysafe_threatmap/config/defaults/actor_metadata.yaml"),
    )
    with pytest.raises(SectorNotFoundError):
        service.build_profile(["unknown"], SectorProfileOptions())
