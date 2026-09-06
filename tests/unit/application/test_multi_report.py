"""Tests for deterministic multi-report aggregation."""

from pathlib import Path

from odysafe_threatmap.application.multi_report import AggregateOptions, MultiReportService
from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl
from odysafe_threatmap.infrastructure.extraction.iocsearcher_adapter import IocsearcherAdapter
from odysafe_threatmap.infrastructure.extraction.pipeline import ExtractionPipeline


class NoSupplementalExtraction:
    """Offline supplemental extractor test double."""

    def extract(self, file_path: Path):
        """Return no supplemental extraction results."""
        from odysafe_threatmap.domain.models import ExtractionResult

        return ExtractionResult()


def test_detects_duplicate_reports_and_false_corroboration(tmp_path: Path) -> None:
    """Duplicate hashes are skipped and only explicit source mappings enable a false finding."""
    root = Path(__file__).parents[3]
    first = tmp_path / "one.txt"
    second = tmp_path / "two.txt"
    content = "T1566.001 evil.example\n"
    first.write_text(content, encoding="utf-8")
    second.write_text(content.replace("evil.example", "other.example"), encoding="utf-8")
    mapping = tmp_path / "sources.csv"
    mapping.write_text(
        "report,source_name,primary_source_id,published_date\none.txt,Publisher,source-1,2026-01-01\ntwo.txt,Publisher,source-1,2026-01-02\n",
        encoding="utf-8",
    )
    repository = AttackRepositoryImpl(root / "tests/fixtures/attack/enterprise-attack-test.json")
    service = MultiReportService(
        ExtractionPipeline(IocsearcherAdapter(), NoSupplementalExtraction(), repository), repository
    )
    result = service.aggregate_reports([tmp_path], AggregateOptions(source_mapping_path=mapping))
    assert len(result.reports) == 2
    assert any(item.item_id == "T1566.001" and item.corroboration_status == "false" for item in result.corroboration)
