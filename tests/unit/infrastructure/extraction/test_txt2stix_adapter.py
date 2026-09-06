"""Tests for the fail-closed txt2stix offline policy facade."""

from pathlib import Path

import pytest

from odysafe_threatmap.domain.exceptions import OfflinePolicyViolation
from odysafe_threatmap.infrastructure.extraction.txt2stix_adapter import (
    Txt2stixAdapter,
    Txt2stixOfflineConfig,
    load_offline_config,
)

DEFAULT_POLICY = (
    Path(__file__).parents[4] / "src" / "odysafe_threatmap" / "config" / "defaults" / "txt2stix_offline.yaml"
)


def test_default_policy_is_strict_and_returns_no_unsafe_supplemental_data() -> None:
    """The default policy does not import or execute unsafe txt2stix paths."""
    adapter = Txt2stixAdapter(load_offline_config(DEFAULT_POLICY))
    report = Path(__file__).parents[3] / "fixtures" / "reports" / "report_test_1.txt"

    assert adapter.extract(report).indicators == []
    with pytest.raises(OfflinePolicyViolation, match="not allowlisted"):
        adapter.assert_slug_allowed("lookup_mitre_attack_enterprise_id")


def test_ai_pattern_is_rejected_before_any_extraction() -> None:
    """AI extractors are prohibited regardless of their configured provider."""
    with pytest.raises(OfflinePolicyViolation, match="Forbidden"):
        Txt2stixOfflineConfig(
            relationship_mode="standard",
            no_remote=True,
            allowed_patterns=("ai_ipv4_address_only",),
        )
