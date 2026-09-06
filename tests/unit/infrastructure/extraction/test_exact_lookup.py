"""Tests for exact ATT&CK identifier validation."""

from pathlib import Path

from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl
from odysafe_threatmap.infrastructure.extraction.exact_lookup import normalize_ttp_id, validate_ttp_id


def test_normalize_ttp_id_uppercases_explicit_identifier() -> None:
    """Explicit ATT&CK identifiers are normalized without semantic matching."""
    assert normalize_ttp_id(" t1059.001 ") == "T1059.001"


def test_validate_ttp_id_uses_local_attack_repository() -> None:
    """Only local ATT&CK records make an explicit identifier valid."""
    bundle_path = Path(__file__).parents[3] / "fixtures" / "attack" / "enterprise-attack-test.json"
    repository = AttackRepositoryImpl(bundle_path)

    assert validate_ttp_id("t1059", repository)
    assert not validate_ttp_id("T9999", repository)
    assert not validate_ttp_id("not-a-technique", repository)
