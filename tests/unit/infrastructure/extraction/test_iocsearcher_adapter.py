"""Tests for the canonical iocsearcher extraction adapter."""

from pathlib import Path

from odysafe_threatmap.infrastructure.extraction.iocsearcher_adapter import IocsearcherAdapter

REPORTS_DIRECTORY = Path(__file__).parents[3] / "fixtures" / "reports"


def test_extracts_indicators_ttps_offsets_and_defanged_values() -> None:
    """IOC extraction preserves normalized values, positions, and provenance."""
    result = IocsearcherAdapter().extract(REPORTS_DIRECTORY / "report_test_1.txt")

    domains = [indicator for indicator in result.indicators if indicator.normalized_value == "evil.com"]
    ttps = {ttp.attack_id: ttp for ttp in result.ttps}
    assert domains[0].defanged
    assert domains[0].first_offset >= 0
    assert domains[0].first_line > 0
    assert domains[0].extraction_engine == "iocsearcher"
    assert ttps["T1059.001"].occurrences == 2
    assert ttps["T1059.001"].offsets
    assert result.word_count > 0
    assert result.line_count > 0


def test_reports_with_no_explicit_ttps_return_an_empty_ttp_list() -> None:
    """Observables alone do not create inferred ATT&CK techniques."""
    result = IocsearcherAdapter().extract(REPORTS_DIRECTORY / "report_test_3.txt")

    assert result.indicators
    assert result.ttps == []


def test_technique_only_report_has_no_indicators() -> None:
    """Explicit ATT&CK IDs are not also represented as indicators."""
    result = IocsearcherAdapter().extract(REPORTS_DIRECTORY / "report_test_2.txt")

    assert result.indicators == []
    assert {ttp.attack_id for ttp in result.ttps} == {"T1059", "T1566.001"}
