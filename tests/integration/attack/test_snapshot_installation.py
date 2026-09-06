"""Atomic, content-addressed ATT&CK snapshot installation tests."""

from pathlib import Path

import pytest

from odysafe_threatmap.domain.exceptions import AttackDataInvalidError, CacheInvalidError
from odysafe_threatmap.infrastructure.attack import installer
from odysafe_threatmap.infrastructure.attack.installer import install_bundle
from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl
from odysafe_threatmap.storage.manifest import load_manifest

FIXTURES = Path(__file__).parents[2] / "fixtures" / "attack"


def test_mutable_source_creates_distinct_sha_snapshots_and_can_reactivate_old_snapshot(
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "manifest.json"
    cache_path = tmp_path / "cache.sqlite"
    data_dir = tmp_path / "data"
    common = {
        "source_kind": "mitre-cti-master",
        "source_url": "https://example.invalid/enterprise-attack.json",
        "source_ref": "master",
    }

    old = install_bundle(
        FIXTURES / "enterprise-attack-legacy-test.json",
        data_dir,
        cache_db_path=cache_path,
        manifest_path=manifest_path,
        **common,
    )
    new = install_bundle(
        FIXTURES / "enterprise-attack-current-test.json",
        data_dir,
        cache_db_path=cache_path,
        manifest_path=manifest_path,
        **common,
    )

    assert old.sha256 != new.sha256
    assert old.bundle_path != new.bundle_path
    assert old.bundle_path.is_file() and new.bundle_path.is_file()
    assert load_manifest(manifest_path) == new
    assert AttackRepositoryImpl(old.bundle_path).get_capabilities().detection_route == "legacy-data-component"
    assert AttackRepositoryImpl(new.bundle_path).get_capabilities().detection_route == "detection-strategy"

    reactivated = install_bundle(
        old.bundle_path,
        data_dir,
        cache_db_path=cache_path,
        manifest_path=manifest_path,
        **common,
    )
    assert reactivated.sha256 == old.sha256
    assert reactivated.bundle_path == old.bundle_path
    assert load_manifest(manifest_path) == reactivated


def test_failed_install_preserves_active_manifest(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    active = install_bundle(
        FIXTURES / "enterprise-attack-legacy-test.json",
        tmp_path / "data",
        cache_db_path=tmp_path / "cache.sqlite",
        manifest_path=manifest_path,
    )
    invalid = tmp_path / "invalid.json"
    invalid.write_text("not-json", encoding="utf-8")

    with pytest.raises(AttackDataInvalidError):
        install_bundle(invalid, tmp_path / "data", manifest_path=manifest_path)

    assert load_manifest(manifest_path) == active


def test_schema_failure_and_interruption_before_manifest_commit_preserve_active_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path = tmp_path / "manifest.json"
    active = install_bundle(
        FIXTURES / "enterprise-attack-legacy-test.json",
        tmp_path / "data",
        cache_db_path=tmp_path / "cache.sqlite",
        manifest_path=manifest_path,
    )
    unsupported = tmp_path / "stix21.json"
    unsupported.write_text(
        '{"type":"bundle","spec_version":"2.1","objects":['
        '{"type":"attack-pattern","spec_version":"2.1",'
        '"x_mitre_domains":["enterprise-attack"]}]}',
        encoding="utf-8",
    )
    with pytest.raises(AttackDataInvalidError, match="STIX 2.1"):
        install_bundle(unsupported, tmp_path / "data", manifest_path=manifest_path)
    assert load_manifest(manifest_path) == active

    def interrupted_cache_build(_bundle: Path, _cache: Path) -> None:
        raise CacheInvalidError("simulated interruption before activation")

    monkeypatch.setattr(installer, "build_cache", interrupted_cache_build)
    with pytest.raises(CacheInvalidError, match="simulated interruption"):
        install_bundle(
            FIXTURES / "enterprise-attack-current-test.json",
            tmp_path / "data",
            cache_db_path=tmp_path / "cache.sqlite",
            manifest_path=manifest_path,
        )
    assert load_manifest(manifest_path) == active
