"""Navigator layer CLI commands."""

from importlib.resources import files
from pathlib import Path

import typer
from rich.console import Console

from odysafe_threatmap.application.actor_snapshot import ActorSnapshotOptions, ActorSnapshotService
from odysafe_threatmap.application.navigator_service import NavigatorOptions, NavigatorResult, NavigatorService
from odysafe_threatmap.application.report_bundle import ReportBundleService, ReportMetadataOptions
from odysafe_threatmap.application.sector_profile import SectorProfileOptions, SectorProfileService
from odysafe_threatmap.config.loader import load_actor_metadata
from odysafe_threatmap.domain.exceptions import ActorNotFoundError, SectorNotFoundError
from odysafe_threatmap.exporters.navigator.exporter import create_layer, save_layer
from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl
from odysafe_threatmap.infrastructure.extraction.iocsearcher_adapter import IocsearcherAdapter
from odysafe_threatmap.infrastructure.extraction.pipeline import ExtractionPipeline
from odysafe_threatmap.infrastructure.extraction.txt2stix_adapter import Txt2stixAdapter, load_offline_config
from odysafe_threatmap.storage.manifest import load_manifest
from odysafe_threatmap.utils.filenames import ensure_output_dir, generate_output_filename

app = typer.Typer(help="Generate local ATT&CK Navigator layers.", no_args_is_help=True)
console = Console()


def _repository() -> AttackRepositoryImpl:
    manifest = load_manifest()
    if manifest is None or not manifest.bundle_path.is_file():
        console.print("[red]✗ No local MITRE ATT&CK data is installed.[/red]")
        raise typer.Exit(code=3)
    return AttackRepositoryImpl(manifest.bundle_path)


def _write(result: NavigatorResult, output: Path) -> None:
    directory = ensure_output_dir(output)
    paths = [
        save_layer(
            create_layer(layer), directory / generate_output_filename("navigator", layer.name, "json", directory)
        )
        for layer in result.layers
    ]
    console.print(f"{len(paths)} Navigator layers created")
    for path in paths:
        console.print(f"JSON created: {path}")


@app.command("report")
def report(
    file_path: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("odysafe-output")),
    presence: bool = typer.Option(True),
    frequency: bool = typer.Option(True),
    mitigations: bool = typer.Option(True),
) -> None:
    """Generate layers from the normalized Module A report result."""
    repository = _repository()
    policy = Path(str(files("odysafe_threatmap.config").joinpath("defaults/txt2stix_offline.yaml")))
    pipeline = ExtractionPipeline(IocsearcherAdapter(), Txt2stixAdapter(load_offline_config(policy)), repository)
    result = ReportBundleService(pipeline, repository).build_bundle(file_path, ReportMetadataOptions())
    _write(
        NavigatorService(repository).generate_from_report(
            result, NavigatorOptions(presence=presence, frequency=frequency, mitigations=mitigations)
        ),
        output,
    )


@app.command("actor")
def actor(
    actor_identifiers: list[str] = typer.Argument(...),
    output: Path = typer.Option(Path("odysafe-output")),
    presence: bool = typer.Option(True),
    frequency: bool = typer.Option(True),
    mitigations: bool = typer.Option(True),
) -> None:
    """Generate layers from the normalized Module B actor result."""
    repository = _repository()
    try:
        result = ActorSnapshotService(repository).build_snapshot(actor_identifiers, ActorSnapshotOptions())
    except ActorNotFoundError as error:
        console.print(f"[red]✗ {error}[/red]")
        raise typer.Exit(code=2) from error
    _write(
        NavigatorService(repository).generate_from_actor(
            result, NavigatorOptions(presence=presence, frequency=frequency, mitigations=mitigations)
        ),
        output,
    )


@app.command("sector")
def sector(
    sector_names: list[str] = typer.Argument(...),
    output: Path = typer.Option(Path("odysafe-output")),
    presence: bool = typer.Option(True),
    frequency: bool = typer.Option(True),
    mitigations: bool = typer.Option(True),
) -> None:
    """Generate layers from the normalized Module C sector result."""
    repository = _repository()
    metadata = load_actor_metadata(
        Path(str(files("odysafe_threatmap.config").joinpath("defaults/actor_metadata.yaml")))
    )
    try:
        result = SectorProfileService(repository, metadata).build_profile(sector_names, SectorProfileOptions())
    except SectorNotFoundError as error:
        console.print(f"[red]✗ {error}[/red]")
        raise typer.Exit(code=2) from error
    _write(
        NavigatorService(repository).generate_from_sector(
            result, NavigatorOptions(presence=presence, frequency=frequency, mitigations=mitigations)
        ),
        output,
    )
