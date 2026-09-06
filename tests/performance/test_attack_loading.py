"""Non-flaky performance invariants for local ATT&CK loading."""

from pathlib import Path

from odysafe_threatmap.infrastructure.attack.loader import load_attack_data


def test_attack_loader_reuses_process_local_instance() -> None:
    """Loading an identical bundle twice reuses the lazy process-local object."""
    bundle = Path(__file__).parents[1] / "fixtures/attack/enterprise-attack-test.json"
    assert load_attack_data(bundle) is load_attack_data(bundle)
