"""Sigma coverage CLI command."""

from importlib.resources import files
from pathlib import Path

import typer
from rich.console import Console

from odysafe_threatmap.application.sigma_coverage import SigmaCoverageOptions, SigmaCoverageResult, SigmaCoverageService
from odysafe_threatmap.config.loader import load_tactic_impact
from odysafe_threatmap.exporters.excel.sigma_coverage import build_coverage_workbook
from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl
from odysafe_threatmap.infrastructure.extraction.iocsearcher_adapter import IocsearcherAdapter
from odysafe_threatmap.infrastructure.extraction.pipeline import ExtractionPipeline
from odysafe_threatmap.infrastructure.extraction.txt2stix_adapter import Txt2stixAdapter, load_offline_config
from odysafe_threatmap.storage.manifest import load_manifest
from odysafe_threatmap.utils.filenames import ensure_output_dir, generate_output_filename

app = typer.Typer(help="Analyze strict Sigma ATT&CK tag coverage.", no_args_is_help=True)
console = Console()


@app.command("sigma")
def sigma(
    report: Path = typer.Argument(..., exists=True, dir_okay=False),
    sigma_directory: Path = typer.Argument(..., exists=True, file_okay=False),
    output: Path = typer.Option(Path("odysafe-output")),
    include_rules: bool = typer.Option(False),
    strict: bool = typer.Option(False),
) -> tuple[SigmaCoverageResult, Path]:
    """Analyze coverage for explicit ATT&CK IDs in one local report."""
    return sigma_paths(report, sigma_directory, output, include_rules, strict)


def sigma_paths(
    report: Path,
    sigma_source: Path | list[Path],
    output: Path,
    include_rules: bool,
    strict: bool,
) -> tuple[SigmaCoverageResult, Path]:
    """Analyze coverage using a directory or explicit interactive rule selection."""
    manifest = load_manifest()
    if manifest is None or not manifest.bundle_path.is_file():
        console.print("[red]✗ No local MITRE ATT&CK data is installed.[/red]")
        raise typer.Exit(code=3)
    repository = AttackRepositoryImpl(manifest.bundle_path)
    defaults = files("odysafe_threatmap.config").joinpath("defaults")
    weights = {
        name: int(value["weight"])
        for name, value in load_tactic_impact(Path(str(defaults.joinpath("tactic_impact.yaml")))).tactics.items()
    }
    policy = Path(str(defaults.joinpath("txt2stix_offline.yaml")))
    pipeline = ExtractionPipeline(IocsearcherAdapter(), Txt2stixAdapter(load_offline_config(policy)), repository)
    try:
        result = SigmaCoverageService(pipeline, repository, weights).analyze_coverage(
            report, sigma_source, SigmaCoverageOptions(include_rules=include_rules, strict=strict)
        )
    except ValueError as error:
        console.print(f"[red]✗ {error}[/red]")
        raise typer.Exit(code=2) from error
    directory = ensure_output_dir(output)
    path = directory / generate_output_filename("sigma_coverage", report.stem, "xlsx", directory)
    build_coverage_workbook(result, path, "odysafe-threatmap coverage sigma")
    total = len(result.coverage)
    console.print(f"{total} techniques analyzed")
    console.print(f"{result.exact_count} exact ({result.exact_count / total * 100 if total else 0:.0f}%)")
    console.print(f"{result.partial_count} partial")
    console.print(f"{result.none_count} not covered")
    console.print(f"Excel created: {path}")
    return result, path
