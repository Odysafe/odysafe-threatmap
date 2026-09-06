"""Tests for format-neutral Navigator preparation."""

from pathlib import Path

from odysafe_threatmap.application.navigator_service import NavigatorOptions, NavigatorService
from odysafe_threatmap.application.report_bundle import ReportBundleService, ReportMetadataOptions
from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl
from odysafe_threatmap.infrastructure.extraction.iocsearcher_adapter import IocsearcherAdapter
from odysafe_threatmap.infrastructure.extraction.pipeline import ExtractionPipeline


class NoSupplementalExtraction:
    """Offline supplemental extractor test double."""

    def extract(self, file_path: Path):
        """Return no supplemental extraction results."""
        from odysafe_threatmap.domain.models import ExtractionResult

        return ExtractionResult()


def test_report_generates_three_normalized_layers() -> None:
    """Validated report techniques feed presence, frequency, and mitigation layers."""
    root = Path(__file__).parents[3]
    repository = AttackRepositoryImpl(root / "tests/fixtures/attack/enterprise-attack-test.json")
    report = ReportBundleService(
        ExtractionPipeline(IocsearcherAdapter(), NoSupplementalExtraction(), repository), repository
    ).build_bundle(root / "tests/fixtures/reports/report_test_1.txt", ReportMetadataOptions())
    result = NavigatorService(repository).generate_from_report(report, NavigatorOptions())
    assert [item.kind for item in result.layers] == ["presence", "frequency", "mitigations"]
    assert result.layers[1].frequencies[0].frequency > 0
