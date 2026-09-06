"""Offline integration tests for the local ATT&CK layer."""

from pathlib import Path

import pytest

from odysafe_threatmap.infrastructure.attack.installer import install_bundle
from odysafe_threatmap.infrastructure.attack.loader import clear_loaded_attack_data, load_attack_data
from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl
from odysafe_threatmap.storage.manifest import load_manifest


@pytest.fixture(autouse=True)
def reset_loaded_data() -> None:
    """Keep process-local loading independent between tests."""
    clear_loaded_attack_data()
    yield
    clear_loaded_attack_data()


@pytest.fixture()
def bundle_path() -> Path:
    """Return the static minimal Enterprise ATT&CK fixture."""
    return Path(__file__).parents[2] / "fixtures" / "attack" / "enterprise-attack-test.json"


def test_install_load_and_query_local_bundle(bundle_path: Path, tmp_path: Path) -> None:
    """Installation, loading, and repository queries remain entirely local."""
    manifest_path = tmp_path / "config" / "attack-manifest.json"
    manifest = install_bundle(
        bundle_path,
        tmp_path / "data",
        cache_db_path=tmp_path / "cache" / "attack.sqlite",
        manifest_path=manifest_path,
    )

    data = load_attack_data(manifest.bundle_path)
    repository = AttackRepositoryImpl(manifest.bundle_path)
    technique = repository.get_technique("T1566.001")

    assert data.get_techniques(remove_revoked_deprecated=True)
    assert load_manifest(manifest_path) == manifest
    assert technique is not None
    assert technique.groups_count == 1
    assert repository.get_group("example alias") is not None
    assert [value.attack_id for value in repository.get_techniques()] == ["T1566.001", "T1059"]
    assert repository.get_technique("T9998") is None
    assert repository.get_technique("T9997") is None
