"""Regenerate visual showcase workbooks through the real offline pipelines."""

from pathlib import Path

from odysafe_threatmap.application.actor_snapshot import ActorSnapshotOptions, ActorSnapshotService
from odysafe_threatmap.application.multi_report import AggregateOptions, MultiReportService
from odysafe_threatmap.application.report_bundle import ReportBundleService, ReportMetadataOptions
from odysafe_threatmap.application.sector_profile import SectorProfileOptions, SectorProfileService
from odysafe_threatmap.application.sigma_coverage import SigmaCoverageOptions, SigmaCoverageService
from odysafe_threatmap.config.loader import load_actor_metadata, load_priority_thresholds, load_tactic_impact
from odysafe_threatmap.domain.models import ExtractionResult
from odysafe_threatmap.exporters.excel.actor_snapshot import build_actor_workbook
from odysafe_threatmap.exporters.excel.multi_report import build_aggregate_workbook
from odysafe_threatmap.exporters.excel.report_bundle import write_report_bundle_workbook
from odysafe_threatmap.exporters.excel.sector_profile import build_sector_workbook
from odysafe_threatmap.exporters.excel.sigma_coverage import build_coverage_workbook
from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl
from odysafe_threatmap.infrastructure.extraction.iocsearcher_adapter import IocsearcherAdapter
from odysafe_threatmap.infrastructure.extraction.pipeline import ExtractionPipeline


class NoSupplementalExtraction:
    def extract(self, file_path: Path) -> ExtractionResult:
        return ExtractionResult()


def main() -> None:
    root = Path(__file__).parents[2]
    fixtures = root / "tests/fixtures/showcase"
    output = root / "tests/golden"
    repository = AttackRepositoryImpl(fixtures / "attack/enterprise-attack-showcase.json")
    pipeline = ExtractionPipeline(IocsearcherAdapter(), NoSupplementalExtraction(), repository)
    report = fixtures / "reports/demo_rich_report.txt"

    report_result = ReportBundleService(pipeline, repository).build_bundle(
        report, ReportMetadataOptions(name="Démonstration CTI riche", source="Jeu de données simulé")
    )
    write_report_bundle_workbook(output / "report_showcase.xlsx", report_result, "showcase report build")

    actor_service = ActorSnapshotService(repository)
    build_actor_workbook(
        actor_service.build_snapshot(["G0016"], ActorSnapshotOptions(include_campaigns=True)),
        output / "actor_showcase.xlsx",
        "showcase actor snapshot",
    )
    build_actor_workbook(
        actor_service.build_snapshot(["G0016", "G0018", "G0046"], ActorSnapshotOptions(include_campaigns=True)),
        output / "actor_comparison_showcase.xlsx",
        "showcase actor comparison",
    )

    impacts = load_tactic_impact(fixtures / "config/tactic_impact.yaml")
    thresholds = load_priority_thresholds(fixtures / "config/priorities.yaml")
    tactic_weights = {name: int(item["weight"]) for name, item in impacts.tactics.items()}
    threshold_values = {
        "critical_threshold": thresholds.critical_threshold,
        "high_threshold": thresholds.high_threshold,
        "moderate_threshold": thresholds.moderate_threshold,
    }
    sector_result = SectorProfileService(
        repository, load_actor_metadata(fixtures / "config/actor_metadata.yaml")
    ).build_profile(
        ["financial", "government", "technology"],
        SectorProfileOptions(include_regions=True, tactic_weights=tactic_weights, priority_thresholds=threshold_values),
    )
    build_sector_workbook(sector_result, output / "sector_showcase.xlsx", "showcase sector profile")

    reports = sorted((fixtures / "reports").glob("*.txt"))
    aggregate = MultiReportService(pipeline, repository).aggregate_reports(
        reports, AggregateOptions(source_mapping_path=fixtures / "sources.csv")
    )
    build_aggregate_workbook(aggregate, output / "aggregate_showcase.xlsx", "showcase aggregate")

    sigma = SigmaCoverageService(pipeline, repository, tactic_weights).analyze_coverage(
        report, fixtures / "sigma", SigmaCoverageOptions(include_rules=True)
    )
    build_coverage_workbook(sigma, output / "sigma_showcase.xlsx", "showcase sigma coverage")


if __name__ == "__main__":
    main()
