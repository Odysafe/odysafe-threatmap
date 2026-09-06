"""Commands for local MITRE ATT&CK data management."""

from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from odysafe_threatmap.config.loader import compute_embedded_config_hash
from odysafe_threatmap.domain.exceptions import AttackDataError
from odysafe_threatmap.infrastructure.attack.acquisition import (
    MITRE_CTI_MASTER_URL,
    download_master,
    download_release,
    normalize_release,
    resolve_release_from_sha256,
)
from odysafe_threatmap.infrastructure.attack.capabilities import detect_bundle_capabilities
from odysafe_threatmap.infrastructure.attack.index_cache import is_cache_valid
from odysafe_threatmap.infrastructure.attack.installer import install_bundle
from odysafe_threatmap.infrastructure.attack.metadata import compute_bundle_metadata
from odysafe_threatmap.storage.manifest import AttackManifest, load_manifest
from odysafe_threatmap.storage.paths import get_cache_db_path, get_data_dir

app = typer.Typer(help="Manage local MITRE ATT&CK data.", no_args_is_help=True)
console = Console()
NO_LOCAL_DATA_MESSAGE = "No local MITRE ATT&CK data is installed."


def _format_size(size: int) -> str:
    """Format a byte count for terminal display."""
    if size < 1024:
        return f"{size} B"
    return f"{size / 1024:.1f} KiB"


def _install_with_feedback(source_path: Path, **options: Any) -> AttackManifest:
    """Install a bundle while keeping every potentially slow phase visible."""
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=24, pulse_style="bright_cyan"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as installation_progress:
        task_id = installation_progress.add_task("Preparing local installation", total=None)

        def show_stage(description: str) -> None:
            installation_progress.update(task_id, description=description)

        manifest = install_bundle(source_path, get_data_dir(), progress=show_stage, **options)
        installation_progress.update(
            task_id,
            description="ATT&CK validation and local index complete",
            total=1,
            completed=1,
        )
    return manifest


@app.command("install")
def install(
    bundle_path: Path | None = typer.Argument(None, dir_okay=False, readable=True),
    release: str | None = typer.Option(None, "--release", help="Install a reproducible MITRE release."),
) -> None:
    """Install a validated local bundle or a reproducible MITRE release."""
    if (bundle_path is None) == (release is None):
        console.print("[red]✗ Provide either a local bundle path or --release, but not both.[/red]")
        raise typer.Exit(code=2)
    try:
        if release is not None:
            release = normalize_release(release)
            with TemporaryDirectory(prefix="odysafe-attack-release-") as directory:
                downloaded = download_release(release, Path(directory))
                console.print("[green]✓ Download complete.[/green]")
                manifest = _install_with_feedback(
                    downloaded,
                    source_kind="mitre-release",
                    source_ref=f"ATT&CK-v{release}",
                    attack_release=release,
                    requested_release=release,
                    resolved_release=release,
                    attack_release_provenance="explicit-mitre-release",
                    downloaded_at_utc=datetime.now().astimezone(),
                )
        else:
            assert bundle_path is not None
            manifest = _install_with_feedback(bundle_path)
    except AttackDataError as error:
        console.print(f"[red]✗ {error}[/red]")
        raise typer.Exit(code=3) from error
    console.print("[green]✓ Local MITRE ATT&CK data installed.[/green]")
    console.print(f"Version: {manifest.version or 'N/A'}")
    console.print(f"SHA-256: {manifest.sha256}")
    console.print(f"Path: {manifest.bundle_path}")


@app.command("update")
def update() -> None:
    """Explicitly download, validate, and activate the current MITRE CTI master snapshot."""
    try:
        with TemporaryDirectory(prefix="odysafe-attack-master-") as directory:
            temporary_bundle = Path(directory) / "enterprise-attack.json"
            downloaded_at = download_master(temporary_bundle)
            console.print("[green]✓ Download complete.[/green]")
            with Progress(
                SpinnerColumn(style="cyan"),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(bar_width=24, pulse_style="bright_cyan"),
                TimeElapsedColumn(),
                console=console,
                transient=False,
            ) as installation_progress:
                task_id = installation_progress.add_task(
                    "Computing SHA-256 and identifying the ATT&CK release", total=None
                )

                def show_stage(description: str) -> None:
                    installation_progress.update(task_id, description=description)

                resolved_release = resolve_release_from_sha256(str(compute_bundle_metadata(temporary_bundle)["sha256"]))
                manifest = install_bundle(
                    temporary_bundle,
                    get_data_dir(),
                    source_kind="mitre-cti-master",
                    source_url=MITRE_CTI_MASTER_URL,
                    source_ref="master",
                    attack_release=resolved_release,
                    requested_release="latest",
                    resolved_release=resolved_release,
                    attack_release_provenance=("official-sha256-match" if resolved_release else "unknown"),
                    downloaded_at_utc=downloaded_at,
                    progress=show_stage,
                )
                installation_progress.update(
                    task_id,
                    description="ATT&CK validation and local index complete",
                    total=1,
                    completed=1,
                )
            console.print("[green]✓ STIX validation and local index complete.[/green]")
    except AttackDataError as error:
        console.print(f"[red]✗ {error}[/red]")
        raise typer.Exit(code=3) from error
    console.print("[green]✓ MITRE CTI master snapshot installed.[/green]")
    console.print(f"SHA-256: {manifest.sha256}")
    console.print(f"Path: {manifest.bundle_path}")


@app.command("status")
def status() -> None:
    """Display the status of the installed local ATT&CK bundle."""
    manifest = load_manifest()
    if manifest is None or not manifest.bundle_path.is_file():
        console.print(NO_LOCAL_DATA_MESSAGE)
        return
    cache_path = get_cache_db_path(create=False)
    cache_exists = cache_path.is_file()
    cache_date = datetime.fromtimestamp(cache_path.stat().st_mtime).astimezone().isoformat() if cache_exists else "N/A"
    table = Table(
        title="🛡  Local MITRE ATT&CK data",
        title_style="bold cyan",
        header_style="bold white on blue",
        border_style="cyan",
    )
    table.add_column("Property", style="bold cyan", no_wrap=True)
    table.add_column("Value", style="white")
    table.add_row("Bundle path", str(manifest.bundle_path))
    table.add_row("Source type", manifest.source_kind)
    table.add_row("Source URL", manifest.source_url or "N/A")
    table.add_row("Source ref", manifest.source_ref or "N/A")
    table.add_row("ATT&CK release", manifest.attack_release or "unknown")
    table.add_row("Requested release", manifest.requested_release or "N/A")
    table.add_row("Resolved release", manifest.resolved_release or "unknown")
    table.add_row("Release provenance", manifest.attack_release_provenance)
    table.add_row("STIX version", manifest.stix_version)
    table.add_row("mitreattack-python", manifest.mitreattack_python_version)
    table.add_row("SHA-256", manifest.sha256)
    table.add_row("Size", _format_size(manifest.bundle_path.stat().st_size))
    table.add_row("Installed at", manifest.installed_at.isoformat())
    table.add_row("Cache", "present" if cache_exists else "absent")
    table.add_row("Cache valid", "yes" if is_cache_valid(cache_path, manifest.sha256) else "no")
    table.add_row("Cache date", cache_date)
    table.add_row("Configuration hash", compute_embedded_config_hash())
    console.print(table)


@app.command("inspect")
def inspect_bundle(bundle_path: Path | None = typer.Argument(None, dir_okay=False, readable=True)) -> None:
    """Inspect bundle schema characteristics and capabilities without frozen object totals."""
    manifest = load_manifest()
    path = bundle_path or (manifest.bundle_path if manifest else None)
    if path is None:
        console.print(NO_LOCAL_DATA_MESSAGE)
        return
    try:
        profile = detect_bundle_capabilities(path)
    except AttackDataError as error:
        console.print(f"[red]✗ {error}[/red]")
        raise typer.Exit(code=3) from error
    table = Table(
        title="🔎  ATT&CK capability inspection",
        title_style="bold magenta",
        header_style="bold white on magenta",
        border_style="magenta",
    )
    table.add_column("Property", style="bold magenta", no_wrap=True)
    table.add_column("Value", style="white")
    if bundle_path is None and manifest is not None:
        table.add_row("Requested release", manifest.requested_release or "N/A")
        table.add_row("Resolved release", manifest.resolved_release or "unknown")
        table.add_row("Source type", manifest.source_kind)
        table.add_row("Source URL/identifier", manifest.source_url or manifest.source_ref or "local-file")
        table.add_row("Bundle SHA-256", manifest.sha256)
        table.add_row("Active snapshot", str(manifest.bundle_path))
    table.add_row("Compatibility", profile.compatibility.value)
    table.add_row("STIX version", profile.stix_version)
    table.add_row("Domain", profile.domain)
    table.add_row("Detection route", profile.detection_route or "unavailable")
    table.add_row("Object types", ", ".join(profile.object_types))
    table.add_row("Relationship types", ", ".join(profile.relationship_types))
    table.add_row("Unknown object types", ", ".join(profile.unknown_object_types) or "none")
    table.add_row("ATT&CK schema/spec versions observed", ", ".join(profile.attack_spec_versions) or "unknown")
    console.print(table)
