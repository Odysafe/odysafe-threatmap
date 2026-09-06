"""Tests for the Report to CTI Bundle application service."""

from pathlib import Path

import pytest

from odysafe_threatmap.application.report_bundle import ReportBundleService, ReportMetadataOptions
from odysafe_threatmap.domain.scoring import interpret_cti_density
from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl
from odysafe_threatmap.infrastructure.extraction.iocsearcher_adapter import IocsearcherAdapter
from odysafe_threatmap.infrastructure.extraction.pipeline import ExtractionPipeline


class NoSupplementalExtraction:
    """Offline test double for the fail-closed supplemental adapter."""

    def extract(self, file_path: Path):
        """Return no supplemental extraction results."""
        from odysafe_threatmap.domain.models import ExtractionResult

        return ExtractionResult()


def _service() -> ReportBundleService:
    root = Path(__file__).parents[3]
    repository = AttackRepositoryImpl(root / "tests" / "fixtures" / "attack" / "enterprise-attack-test.json")
    pipeline = ExtractionPipeline(IocsearcherAdapter(), NoSupplementalExtraction(), repository)
    return ReportBundleService(pipeline, repository)


def test_service_enriches_ttps_detects_exact_actors_and_calculates_density() -> None:
    """The service produces domain data without importing any Excel component."""
    root = Path(__file__).parents[3]
    result = _service().build_bundle(
        root / "tests" / "fixtures" / "reports" / "report_test_1.txt", ReportMetadataOptions()
    )

    assert [technique.attack_id for technique in result.techniques] == ["T1566.001"]
    assert [actor.name for actor in result.detected_actors] == ["Example Group"]
    assert result.associated_groups[0].actor.name == "Example Group"
    expected_density = (
        (
            sum(item.occurrences for item in result.extraction_result.indicators)
            + sum(item.occurrences for item in result.extraction_result.ttps)
        )
        / result.report_metadata.word_count
        * 1000
    )
    assert result.cti_density == expected_density


@pytest.mark.parametrize(
    ("density", "label"),
    [
        (None, "Not available"),
        (0.0, "No detected observations"),
        (9.9, "Low concentration"),
        (10.0, "Moderate concentration"),
        (50.0, "High concentration"),
        (100.0, "Very high concentration"),
    ],
)
def test_cti_density_interpretation_is_value_specific_and_not_a_risk_score(density: float | None, label: str) -> None:
    interpretation = interpret_cti_density(density)

    assert interpretation.label == label
    if density is not None:
        assert f"{density:.1f}" in interpretation.explanation
        assert "not a danger" in interpretation.explanation


def test_service_handles_a_poor_report_without_an_error() -> None:
    """A report without structured CTI data still has valid traceability metadata."""
    root = Path(__file__).parents[3]
    result = _service().build_bundle(
        root / "tests" / "fixtures" / "reports" / "report_poor.txt", ReportMetadataOptions()
    )

    assert result.extraction_result.indicators == []
    assert result.extraction_result.ttps == []
    assert result.techniques == []
    assert result.cti_density == 0.0
