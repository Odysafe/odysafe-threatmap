"""Offline integration tests for the full extraction pipeline."""

from pathlib import Path

from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl
from odysafe_threatmap.infrastructure.extraction.iocsearcher_adapter import IocsearcherAdapter
from odysafe_threatmap.infrastructure.extraction.pipeline import ExtractionPipeline
from odysafe_threatmap.infrastructure.extraction.txt2stix_adapter import Txt2stixAdapter, load_offline_config


def test_pipeline_deduplicates_and_validates_explicit_ttps() -> None:
    """The pipeline retains canonical provenance and marks invalid IDs locally."""
    repository_root = Path(__file__).parents[3]
    repository = AttackRepositoryImpl(repository_root / "tests" / "fixtures" / "attack" / "enterprise-attack-test.json")
    policy = load_offline_config(
        repository_root / "src" / "odysafe_threatmap" / "config" / "defaults" / "txt2stix_offline.yaml"
    )
    pipeline = ExtractionPipeline(IocsearcherAdapter(), Txt2stixAdapter(policy), repository)

    result = pipeline.extract(repository_root / "tests" / "fixtures" / "reports" / "report_test_1.txt")
    ttps = {ttp.attack_id: ttp for ttp in result.ttps}

    assert ttps["T1059.001"].validated is False
    assert ttps["T1566.001"].validated is True
    assert ttps["T1105"].validated is False
    assert ttps["T1566.001"].extraction_engine == "iocsearcher"
    indicator_keys = {(indicator.type, indicator.normalized_value) for indicator in result.indicators}
    assert len(indicator_keys) == len(result.indicators)
