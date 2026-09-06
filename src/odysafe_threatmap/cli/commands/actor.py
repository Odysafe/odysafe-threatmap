"""Threat Actor Snapshot CLI commands."""

from hashlib import sha256
from pathlib import Path

import typer
from rich.console import Console

from odysafe_threatmap.application.actor_snapshot import ActorSnapshotOptions, ActorSnapshotResult, ActorSnapshotService
from odysafe_threatmap.domain.exceptions import ActorNotFoundError, AmbiguousActorError
from odysafe_threatmap.exporters.excel.actor_snapshot import build_actor_workbook
from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl
from odysafe_threatmap.storage.manifest import load_manifest
from odysafe_threatmap.utils.filenames import ensure_output_dir, generate_output_filename

app = typer.Typer(help="Build local ATT&CK threat actor snapshots.", no_args_is_help=True)
console = Console()


def _output_label(result: ActorSnapshotResult) -> str:
    """Return a concise, stable label describing every selected actor."""
    if len(result.actors) == 1:
        return result.actors[0].name
    actor_ids = sorted(actor.attack_id for actor in result.actors)
    fingerprint = sha256("\0".join(actor_ids).encode()).hexdigest()[:8]
    return f"comparison_{len(actor_ids)}-groups_{fingerprint}"


@app.command("snapshot")
def snapshot(
    actor_identifiers: list[str] = typer.Argument(..., metavar="ACTOR [ACTOR... ]"),
    output: Path = typer.Option(Path("odysafe-output")),
    navigator: bool = typer.Option(False),
    include_campaigns: bool = typer.Option(True, "--include-campaigns/--no-include-campaigns"),
    include_local_metadata: bool = typer.Option(False),
) -> tuple[ActorSnapshotResult, Path]:
    """Build an offline Excel snapshot for one or more ATT&CK groups."""
    manifest = load_manifest()
    if manifest is None or not manifest.bundle_path.is_file():
        console.print("[red]✗ No local MITRE ATT&CK data is installed.[/red]")
        raise typer.Exit(code=3)
    repository = AttackRepositoryImpl(manifest.bundle_path)
    service = ActorSnapshotService(repository)
    try:
        result = service.build_snapshot(
            actor_identifiers,
            ActorSnapshotOptions(
                include_campaigns=include_campaigns,
                include_local_metadata=include_local_metadata,
            ),
        )
    except (ActorNotFoundError, AmbiguousActorError) as error:
        console.print(f"[red]✗ {error}[/red]")
        raise typer.Exit(code=2) from error
    output_directory = ensure_output_dir(output)
    output_name = generate_output_filename("actor", _output_label(result), "xlsx", output_directory)
    output_path = output_directory / output_name
    build_actor_workbook(output_path=output_path, snapshot_result=result, command="odysafe-threatmap actor snapshot")
    console.print(f"{len(result.actors)} actors resolved")
    console.print(f"{len(result.techniques)} total TTPs")
    console.print(f"{len(result.software)} software records")
    console.print(f"{len(result.campaigns)} campaigns")
    console.print(f"Excel created: {output_path}")
    if navigator:
        console.print("⚠ Navigator generation is deferred to P08.")
    return result, output_path
