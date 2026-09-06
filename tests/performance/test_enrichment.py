"""Non-flaky ATT&CK enrichment invariants."""

from pathlib import Path

from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl


def test_enrichment_returns_a_stable_technique_for_repeated_lookup() -> None:
    """Repeated exact lookups produce equivalent local ATT&CK data."""
    bundle = Path(__file__).parents[1] / "fixtures/attack/enterprise-attack-test.json"
    repository = AttackRepositoryImpl(bundle)
    assert repository.get_technique("T1566.001") == repository.get_technique("T1566.001")
