"""Multi-report aggregation CLI command."""

from importlib.resources import files
from pathlib import Path

import typer
from rich.console import Console

from odysafe_threatmap.application.multi_report import AggregateOptions, AggregateResult, MultiReportService
from odysafe_threatmap.exporters.excel.multi_report import build_aggregate_workbook
from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl
from odysafe_threatmap.infrastructure.extraction.iocsearcher_adapter import IocsearcherAdapter
from odysafe_threatmap.infrastructure.extraction.pipeline import ExtractionPipeline
from odysafe_threatmap.infrastructure.extraction.txt2stix_adapter import Txt2stixAdapter, load_offline_config
from odysafe_threatmap.storage.manifest import load_manifest
from odysafe_threatmap.utils.filenames import ensure_output_dir

console = Console()


def aggregate(
    directory: Path = typer.Argument(..., exists=True, file_okay=False),
    recursive: bool = typer.Option(False),
    sources: Path | None = typer.Option(None),
    output: Path = typer.Option(Path("odysafe-output")),
    overwrite: bool = typer.Option(False),
) -> tuple[AggregateResult, Path]:
    """Aggregate supported local report documents into one offline Excel workbook."""
    return aggregate_paths([directory], recursive, sources, output, overwrite)


def aggregate_paths(
    report_paths: list[Path],
    recursive: bool = False,
    sources: Path | None = None,
    output: Path = Path("odysafe-output"),
    overwrite: bool = False,
) -> tuple[AggregateResult, Path]:
    """Aggregate explicitly selected reports for the interactive front end."""
    manifest = load_manifest()
    if manifest is None or not manifest.bundle_path.is_file():
        console.print("[red]✗ No local MITRE ATT&CK data is installed.[/red]")
        raise typer.Exit(code=3)
    repository = AttackRepositoryImpl(manifest.bundle_path)
    policy = Path(str(files("odysafe_threatmap.config").joinpath("defaults/txt2stix_offline.yaml")))
    pipeline = ExtractionPipeline(IocsearcherAdapter(), Txt2stixAdapter(load_offline_config(policy)), repository)
    try:
        result = MultiReportService(pipeline, repository).aggregate_reports(
            report_paths, AggregateOptions(recursive=recursive, source_mapping_path=sources)
        )
    except ValueError as error:
        console.print(f"[red]✗ {error}[/red]")
        raise typer.Exit(code=2) from error
    destination = ensure_output_dir(output) / "aggregate.xlsx"
    if destination.exists() and not overwrite:
        console.print(f"[red]✗ Output exists: {destination}. Use --overwrite to replace it.[/red]")
        raise typer.Exit(code=2)
    build_aggregate_workbook(result, destination, "odysafe-threatmap aggregate")
    console.print(f"{len(result.reports)} reports analyzed")
    console.print(f"{len(result.indicators)} unique IOCs")
    console.print(f"{len(result.techniques)} unique TTPs")
    console.print(f"{sum(item.corroboration_status == 'false' for item in result.corroboration)} false corroborations")
    console.print(
        f"{sum(item.corroboration_status == 'multi-source' for item in result.corroboration)} multi-source corroborations"
    )
    console.print(f"Excel created: {destination}")
    return result, destination
