"""Unit tests for the local ATT&CK SQLite cache."""

import shutil
from pathlib import Path

import pytest

from odysafe_threatmap.infrastructure.attack.index_cache import (
    build_cache,
    get_technique_by_attack_id,
    invalidate_cache,
    is_cache_valid,
)
from odysafe_threatmap.infrastructure.attack.metadata import compute_bundle_metadata


@pytest.fixture()
def bundle_path() -> Path:
    """Return the static minimal Enterprise ATT&CK fixture."""
    return Path(__file__).parents[3] / "fixtures" / "attack" / "enterprise-attack-test.json"


def test_build_cache_and_get_technique(bundle_path: Path, tmp_path: Path) -> None:
    """The SQLite cache indexes active techniques and relationship counts."""
    database_path = tmp_path / "attack.sqlite"

    build_cache(bundle_path, database_path)

    technique = get_technique_by_attack_id(database_path, "t1566.001")
    assert technique is not None
    assert technique["name"] == "Spearphishing Attachment"
    assert technique["groups_count"] == 1
    assert technique["software_count"] == 1


def test_cache_validity_uses_bundle_sha256(bundle_path: Path, tmp_path: Path) -> None:
    """A changed bundle hash invalidates the derived cache."""
    copied_bundle = tmp_path / "enterprise-attack.json"
    shutil.copyfile(bundle_path, copied_bundle)
    database_path = tmp_path / "attack.sqlite"
    original_sha256 = str(compute_bundle_metadata(copied_bundle)["sha256"])
    build_cache(copied_bundle, database_path)

    assert is_cache_valid(database_path, original_sha256)
    copied_bundle.write_text(copied_bundle.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    changed_sha256 = str(compute_bundle_metadata(copied_bundle)["sha256"])
    assert not is_cache_valid(database_path, changed_sha256)

    invalidate_cache(database_path)
    assert not database_path.exists()
