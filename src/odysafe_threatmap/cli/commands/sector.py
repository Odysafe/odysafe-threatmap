"""Sector Threat Profile CLI commands."""

import sys
from importlib.resources import files
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn

from odysafe_threatmap.application.sector_profile import SectorProfileOptions, SectorProfileResult, SectorProfileService
from odysafe_threatmap.config.loader import load_actor_metadata, load_priority_thresholds, load_tactic_impact
from odysafe_threatmap.config.sectors import SectorRegistry
from odysafe_threatmap.domain.exceptions import SectorNotFoundError
from odysafe_threatmap.exporters.excel.sector_profile import build_sector_workbook
from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl
from odysafe_threatmap.storage.manifest import load_manifest
from odysafe_threatmap.utils.filenames import ensure_output_dir, generate_output_filename

app = typer.Typer(help="Build local sector threat profiles.", no_args_is_help=True)
console = Console(force_terminal=sys.stdout.isatty(), color_system="standard")


@app.command("profile")
def profile(
    sector_names: list[str] = typer.Argument(..., metavar="SECTOR [SECTOR...]"),
    output: Path = typer.Option(Path("odysafe-output")),
    navigator: bool = typer.Option(False),
    include_regions: bool = typer.Option(False),
) -> list[tuple[SectorProfileResult, Path]]:
    """Build an offline Excel profile from explicit local sector mappings."""
    manifest = load_manifest()
    if manifest is None or not manifest.bundle_path.is_file():
        console.print("[red]✗ No local MITRE ATT&CK data is installed.[/red]")
        raise typer.Exit(code=3)
    defaults = files("odysafe_threatmap.config").joinpath("defaults")
    metadata = load_actor_metadata(Path(str(defaults.joinpath("actor_metadata.yaml"))))
    impact = load_tactic_impact(Path(str(defaults.joinpath("tactic_impact.yaml"))))
    thresholds = load_priority_thresholds(Path(str(defaults.joinpath("priorities.yaml"))))
    weights = {name: int(values["weight"]) for name, values in impact.tactics.items()}
    repository = AttackRepositoryImpl(manifest.bundle_path)
    registry = SectorRegistry.load()
    try:
        canonical_names = registry.resolve_many(sector_names)
    except SectorNotFoundError as error:
        console.print(f"[red]✗ {error}[/red]")
        raise typer.Exit(code=2) from error
    output_directory = ensure_output_dir(output) / "sectors"
    output_directory.mkdir(parents=True, exist_ok=True)
    generated: list[tuple[str, Path]] = []
    outcomes: list[tuple[SectorProfileResult, Path]] = []
    warnings: list[str] = []
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[white]{task.description}"),
        BarColumn(complete_style="cyan", finished_style="green"),
        MofNCompleteColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Preparing sector intelligence", total=len(canonical_names))
        for canonical_name in canonical_names:
            progress.update(task, description=f"Building {canonical_name}")
            result = SectorProfileService(repository, metadata, registry).build_profile(
                [canonical_name],
                SectorProfileOptions(
                    include_regions=include_regions,
                    tactic_weights=weights,
                    priority_thresholds=thresholds.model_dump(),
                ),
            )
            output_path = output_directory / generate_output_filename(
                "sector", canonical_name, "xlsx", output_directory
            )
            build_sector_workbook(result, output_path, "odysafe-threatmap sector profile")
            progress.advance(task)
            generated.append((result.sectors[0].name, output_path))
            outcomes.append((result, output_path))
            warnings.extend(result.warnings)
    console.print(f"[bold green]✓ {len(generated)} sector reports generated[/bold green]")
    for name, output_path in generated:
        console.print(f"  [green]✓[/green] {name}: [cyan]{output_path}[/cyan]")
    for warning in warnings:
        console.print(f"[yellow]⚠ {warning}[/yellow]")
    if navigator:
        console.print("⚠ Navigator generation is deferred to P08.")
    return outcomes
