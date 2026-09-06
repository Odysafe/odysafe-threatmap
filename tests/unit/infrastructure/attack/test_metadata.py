"""Unit tests for ATT&CK bundle validation."""

import json
from pathlib import Path

import pytest

from odysafe_threatmap.domain.exceptions import AttackDataInvalidError
from odysafe_threatmap.infrastructure.attack.metadata import compute_bundle_metadata


@pytest.fixture()
def bundle_path() -> Path:
    """Return the static minimal Enterprise ATT&CK fixture."""
    return Path(__file__).parents[3] / "fixtures" / "attack" / "enterprise-attack-test.json"


def test_compute_bundle_metadata_for_valid_bundle(bundle_path: Path) -> None:
    """A valid Enterprise STIX 2.0 bundle exposes its actual metadata."""
    metadata = compute_bundle_metadata(bundle_path)

    assert metadata["spec_version"] == "2.0"
    assert metadata["version"] == "test-2026.1"
    assert metadata["sha256"]


def test_compute_bundle_metadata_rejects_non_enterprise_bundle(tmp_path: Path) -> None:
    """A syntactically valid bundle without the Enterprise domain is rejected."""
    invalid_bundle = tmp_path / "invalid.json"
    invalid_bundle.write_text(json.dumps({"type": "bundle", "spec_version": "2.0", "objects": []}), encoding="utf-8")

    with pytest.raises(AttackDataInvalidError, match="Enterprise"):
        compute_bundle_metadata(invalid_bundle)
