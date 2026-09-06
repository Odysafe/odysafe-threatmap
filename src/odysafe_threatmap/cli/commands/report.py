"""Report to CTI Bundle CLI commands."""

from importlib.resources import files
from pathlib import Path

import typer
from rich.console import Console

from odysafe_threatmap.application.report_bundle import ReportBundleResult, ReportBundleService, ReportMetadataOptions
from odysafe_threatmap.exporters.excel.report_bundle import write_report_bundle_workbook
from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl
from odysafe_threatmap.infrastructure.extraction.iocsearcher_adapter import IocsearcherAdapter
from odysafe_threatmap.infrastructure.extraction.pipeline import ExtractionPipeline
from odysafe_threatmap.infrastructure.extraction.txt2stix_adapter import Txt2stixAdapter, load_offline_config
from odysafe_threatmap.storage.manifest import load_manifest
from odysafe_threatmap.utils.filenames import ensure_output_dir, generate_output_filename

app = typer.Typer(help="Build CTI bundles from local TXT, HTML, PDF, or DOCX reports.", no_args_is_help=True)
console = Console()


@app.command("build")
def build(
    file_path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    name: str | None = typer.Option(None),
    source: str | None = typer.Option(None),
    published_date: str | None = typer.Option(None, "--date"),
    tlp: str | None = typer.Option(None),
    confidence: str | None = typer.Option(None),
    output: Path = typer.Option(Path("odysafe-output")),
    navigator: bool = typer.Option(False),
    strict: bool = typer.Option(False),
) -> tuple[ReportBundleResult, Path]:
    """Build an offline Excel CTI bundle from a supported local report document."""
    manifest = load_manifest()
    if manifest is None or not manifest.bundle_path.is_file():
        console.print("[red]✗ No local MITRE ATT&CK data is installed.[/red]")
        raise typer.Exit(code=3)
    options = ReportMetadataOptions.model_validate(
        {"name": name, "source": source, "published_date": published_date, "tlp": tlp, "confidence": confidence}
    )
    repository = AttackRepositoryImpl(manifest.bundle_path)
    policy_path = Path(str(files("odysafe_threatmap.config").joinpath("defaults/txt2stix_offline.yaml")))
    pipeline = ExtractionPipeline(IocsearcherAdapter(), Txt2stixAdapter(load_offline_config(policy_path)), repository)
    result = ReportBundleService(pipeline, repository).build_bundle(file_path, options)
    output_directory = ensure_output_dir(output)
    output_name = generate_output_filename("report", result.report_metadata.name, "xlsx", output_directory)
    output_path = output_directory / output_name
    write_report_bundle_workbook(output_path, result, "odysafe-threatmap report build")
    console.print(f"{len(result.extraction_result.indicators)} IOCs extracted")
    console.print(f"{len(result.extraction_result.ttps)} TTPs found")
    console.print(f"{sum(item.validated for item in result.extraction_result.ttps)} valid ATT&CK TTPs")
    console.print(f"{len(result.detected_actors)} explicitly mentioned actors")
    console.print(f"Excel created: {output_path}")
    if not result.extraction_result.indicators and not result.extraction_result.ttps:
        console.print("⚠ No IOC or explicit ATT&CK ID was detected in this report.")
    if navigator:
        console.print("⚠ Navigator generation is deferred to P08.")
    if strict:
        console.print("Strict mode is accepted; no non-fatal extraction warning was produced.")
    return result, output_path
