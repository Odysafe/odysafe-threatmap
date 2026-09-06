"""Small interactive front end that dispatches to existing CLI handlers."""

import sys
import threading
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import TypeVar

import typer
from prompt_toolkit import prompt as toolkit_prompt
from prompt_toolkit.completion import PathCompleter
from prompt_toolkit.shortcuts import checkboxlist_dialog, radiolist_dialog
from prompt_toolkit.styles import Style
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, ProgressColumn, SpinnerColumn, Task, TextColumn
from rich.text import Text

from odysafe_threatmap.cli.commands import actor, coverage, data, report, sector
from odysafe_threatmap.cli.commands.aggregate import aggregate_paths
from odysafe_threatmap.cli.commands.doctor import run_doctor
from odysafe_threatmap.cli.guides import FEATURE_GUIDES, FeatureGuide
from odysafe_threatmap.config.sectors import SectorRegistry
from odysafe_threatmap.domain.exceptions import SectorNotFoundError
from odysafe_threatmap.infrastructure.attack.acquisition import normalize_release
from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl
from odysafe_threatmap.infrastructure.extraction.iocsearcher_adapter import SUPPORTED_REPORT_SUFFIXES
from odysafe_threatmap.storage.manifest import load_manifest
from odysafe_threatmap.storage.paths import BUNDLE_FILENAME, get_data_dir

Reader = Callable[[str], str]
Writer = Callable[[str], None]
ResultT = TypeVar("ResultT")
_console = Console(force_terminal=sys.stdout.isatty(), color_system="standard")


def _installation_root() -> Path:
    """Locate the stable installation root without depending on the launch directory."""
    candidates = (
        Path(sys.executable).resolve().parent.parent,
        Path(__file__).resolve().parents[3],
        Path.cwd(),
    )
    for candidate in candidates:
        if (candidate / "odysafe-input").is_dir() or (candidate / "install.sh").is_file():
            return candidate
    return Path.cwd()


DEFAULT_INPUT_DIRECTORY = _installation_root() / "odysafe-input"
DEFAULT_REPORT_DIRECTORY = DEFAULT_INPUT_DIRECTORY / "reports"
DEFAULT_SIGMA_DIRECTORY = DEFAULT_INPUT_DIRECTORY / "sigma"
DEFAULT_OUTPUT_DIRECTORY = _installation_root() / "odysafe-output"
ACTOR_SELECTOR_STYLE = Style.from_dict(
    {
        "dialog": "bg:#101820",
        "dialog frame.label": "bold #00d7ff",
        "dialog.body": "bg:#101820 #ffffff",
        "checkbox": "#00d7ff",
        "checkbox-selected": "bold #00ff87",
        "button": "bg:#005f87 #ffffff",
        "button.focused": "bg:#00afff #000000 bold",
    }
)


class _ActivityBarColumn(ProgressColumn):
    """Render a moving pulse when an operation cannot report a real percentage."""

    def render(self, task: Task) -> Text:
        width = 24
        if task.finished:
            return Text("█" * width, style="green")
        step = int(task.fields.get("pulse", 0))
        span = 5
        period = 2 * (width - span)
        start = step % period
        if start > width - span:
            start = period - start
        return Text("░" * start + "█" * span + "░" * (width - start - span), style="cyan")


def _styled_write(message: str) -> None:
    _console.print(message, style="white", markup=True)


def _run_with_progress(label: str, action: Callable[[], ResultT], write: Writer) -> ResultT:
    if write is not _styled_write:
        return action()
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[white]{task.description}"),
        _ActivityBarColumn(),
        TextColumn("[cyan]{task.fields[state]}"),
        console=_console,
        refresh_per_second=12,
    ) as progress:
        task = progress.add_task(label, total=1, pulse=0, state="working")
        stopped = threading.Event()

        def animate() -> None:
            pulse = 0
            while not stopped.wait(0.08):
                pulse += 1
                progress.update(task, pulse=pulse)

        animator = threading.Thread(target=animate, name="odysafe-progress", daemon=True)
        animator.start()
        try:
            result = action()
        finally:
            stopped.set()
            animator.join(timeout=1)
        progress.update(task, completed=1, description=f"{label} complete", state="done")
    return result


def _unicode_supported() -> bool:
    encoding = sys.stdout.encoding or "ascii"
    try:
        "🛡✓".encode(encoding)
    except UnicodeEncodeError:
        return False
    return True


def _header(write: Writer, title: str = "THREATMAP") -> None:
    manifest = load_manifest()
    release = manifest.resolved_release or manifest.attack_release if manifest else None
    shield = "🛡" if _unicode_supported() else "#"
    check = "✓" if _unicode_supported() else "OK"
    banner = (
        f"\n[bold bright_cyan]{shield}   ODYSAFE[/bold bright_cyan]\n\n"
        f"[bold white]{' '.join(title)}[/bold white]\n\n"
        "[white]Cyber Threat Intelligence & ATT&CK Intelligence[/white]\n"
    )
    if write is _styled_write:
        _console.print(Panel(Text.from_markup(banner, justify="center"), border_style="bright_cyan", padding=(1, 2)))
    else:
        write(banner)
    if manifest and manifest.bundle_path.is_file():
        write(
            f"  [green]{check} SYSTEM READY[/green]   [white]ATT&CK {release or 'unknown'}   STIX {manifest.stix_version}[/white]"
        )
    else:
        write("  [yellow]⚠ ATT&CK data not installed[/yellow]")


def _sector_selection(read: Reader, write: Writer) -> list[str] | None:
    try:
        registry = SectorRegistry.load()
    except (OSError, ValueError) as error:
        write(f"[bold bright_red]✗ SECTOR CONFIGURATION UNAVAILABLE[/bold bright_red]  [white]{error}[/white]")
        return None
    _header(write, "SECTOR INTELLIGENCE")
    write("\n[bold white]Choose one or more industries.[/bold white]\n")
    unicode = _unicode_supported()
    for index, definition in enumerate(registry.definitions, 1):
        icon = definition.icon if unicode else "-"
        write(f"  [cyan]{index:<3}[/cyan] {icon}  [white]{definition.name}[/white]")
    write("\n[white]Selection[/white]  [dim]Example: 1,2,5 or 1-4[/dim]")
    try:
        selected = registry.resolve_selection(read("\033[1;36m›\033[0m "))
    except SectorNotFoundError as error:
        write(f"[yellow]⚠ {error}[/yellow]")
        return None
    by_id = {item.id: item for item in registry.definitions}
    write("\n[bold white]Selected[/bold white]")
    for sector_id in selected:
        write(
            f"  [green]✓[/green] {by_id[sector_id].name}" if unicode else f"  [green]OK[/green] {by_id[sector_id].name}"
        )
    return selected


def _confirm(prompt: str, read: Reader, write: Writer) -> bool:
    while True:
        answer = read(f"{prompt} [y/N]: ").strip().casefold()
        if answer in {"y", "yes"}:
            return True
        if answer in {"", "n", "no"}:
            return False
        write("Please enter y or n.")


def _inspect(write: Writer) -> None:
    snapshots = sorted(get_data_dir(create=False).rglob(BUNDLE_FILENAME))
    write(f"\n[bold green]📦  Installed snapshots: {len(snapshots)}[/bold green]")
    for snapshot in snapshots:
        write(f"  [cyan]•[/cyan] [white]{snapshot}[/white]")
    data.status()
    data.inspect_bundle(None)


def _install_release(release: str) -> None:
    data.install(None, release)


def _panel(write: Writer, title: str, body: str, border_style: str = "bright_cyan", *, centered: bool = False) -> None:
    if write is _styled_write:
        content: str | Align = Align.center(Text.from_markup(body)) if centered else body
        _console.print(Panel(content, title=title, border_style=border_style, padding=(1, 2)))
    else:
        write(f"{title}\n{body}")


def _render_feature_guide(guide: FeatureGuide, write: Writer) -> None:
    _panel(write, f"{guide.icon}  {guide.title}", guide.summary)
    sections = (
        ("🔎 WHAT THIS DOES", guide.what_it_does, "bright_cyan"),
        ("📥 WHAT YOU NEED", guide.required_inputs, "yellow"),
        ("⚙ OPTIONAL INPUT", guide.optional_inputs, "magenta"),
        ("📤 WHAT YOU GET", guide.outputs, "bright_green"),
        ("⚠ IMPORTANT LIMITATIONS", guide.limitations, "yellow"),
        ("💡 EXAMPLE", guide.examples, "cyan"),
    )
    for heading, items, color in sections:
        write(f"\n[{color}][bold]{heading}[/bold][/{color}]")
        for item in items:
            write(f"  [white]• {item}[/white]")
    _panel(write, "📤 EXPECTED RESULT", guide.expected_result, "bright_green")


def _feature_guide(guide: FeatureGuide, read: Reader, write: Writer) -> bool:
    _render_feature_guide(guide, write)
    write("[bright_cyan]1[/bright_cyan]  [bold white]▶ Continue[/bold white]")
    write("[white]2  ← Back[/white]")
    return read("Continue or Back › ").strip().casefold() in {"1", "", "c", "continue"}


def _read_path(read: Reader, prompt_text: str, initial: str) -> str:
    if read is input and sys.stdin.isatty():
        return toolkit_prompt(
            prompt_text,
            default=initial,
            completer=PathCompleter(expanduser=True, only_directories=False),
            complete_while_typing=False,
        )
    return read(prompt_text)


def _path_input(
    read: Reader,
    write: Writer,
    *,
    title: str,
    prompt: str,
    kind: str,
    default: Path | None = None,
) -> Path | None:
    resolved_default = default.expanduser().resolve() if default is not None else None
    default_text = f"\n\nDefault folder:\n  [bright_cyan]{resolved_default}[/bright_cyan]" if resolved_default else ""
    input_description = "report document (TXT, HTML, PDF, or DOCX)" if kind == "text report" else kind
    inventory = ""
    if resolved_default is not None and kind == "text report":
        candidates = (
            sorted(
                item
                for item in resolved_default.iterdir()
                if item.is_file() and item.suffix.casefold() in SUPPORTED_REPORT_SUFFIXES
            )
            if resolved_default.is_dir()
            else []
        )
        if candidates:
            inventory = "\n\nAvailable reports:\n" + "\n".join(
                f"  [bright_cyan]{item.name}[/bright_cyan]" for item in candidates
            )
        else:
            inventory = (
                "\n\n[yellow]⚠ NO REPORTS IN THE DEFAULT FOLDER[/yellow]\n"
                "Place a TXT, HTML, PDF, or DOCX report in this folder, "
                "or enter another local path."
            )
    elif resolved_default is not None and kind == "directory":
        entries = sorted(item.name for item in resolved_default.iterdir()) if resolved_default.is_dir() else []
        inventory = (
            "\n\nFolder contents:\n" + "\n".join(f"  [bright_cyan]{name}[/bright_cyan]" for name in entries)
            if entries
            else "\n\n[yellow]⚠ THE DEFAULT FOLDER IS EMPTY[/yellow]\nPlace the required files in it or enter another path."
        )
    _panel(
        write,
        title,
        f"Enter a readable local {input_description}.{default_text}{inventory}\n\n"
        "Press Tab to complete paths. Type b, back, q, or quit to return.",
        "yellow",
    )
    while True:
        value = _read_path(read, f"{prompt} › ", str(resolved_default) if resolved_default is not None else "").strip()
        if value.casefold() in {"b", "back", "q", "quit"}:
            return None
        path = Path(value or str(resolved_default or "")).expanduser()
        if kind == "text report" and path.is_dir():
            candidates = sorted(
                item
                for item in path.iterdir()
                if item.is_file() and item.suffix.casefold() in SUPPORTED_REPORT_SUFFIXES
            )
            if len(candidates) == 1:
                path = candidates[0]
            elif candidates:
                write("[yellow]⚠ MULTIPLE REPORTS FOUND[/yellow]  Select one with Tab:")
                for candidate in candidates:
                    write(f"  [cyan]{candidate}[/cyan]")
                continue
            else:
                write(
                    "[bold yellow]⚠ NO SUPPORTED REPORTS FOUND[/bold yellow]  "
                    "Place a TXT, HTML, PDF, or DOCX report in the folder or enter another path."
                )
                continue
        valid = (
            path.is_file() and path.suffix.casefold() in SUPPORTED_REPORT_SUFFIXES
            if kind == "text report"
            else path.is_dir()
        )
        if valid:
            write(f"[bold bright_cyan]{path}[/bold bright_cyan]")
            return path
        label = "REPORT NOT FOUND OR UNSUPPORTED FORMAT" if kind == "text report" else "DIRECTORY NOT FOUND"
        write(f"[bold bright_red]✗ {label}[/bold bright_red]  [white]{path}[/white]")


def _attack_summary(write: Writer, input_text: str, output: Path, expected: str) -> None:
    manifest = load_manifest()
    release = manifest.resolved_release or manifest.attack_release if manifest else "N/A"
    sha = manifest.sha256[:16] + "…" if manifest else "N/A"
    source = manifest.source_kind if manifest else "N/A"
    body = (
        f"[yellow]📥 INPUT[/yellow]\n  [bright_cyan]{input_text}[/bright_cyan]\n\n"
        f"[bright_cyan]🛡 MITRE ATT&CK[/bright_cyan]\n"
        f"  Release: {release or 'N/A'}  •  STIX: {manifest.stix_version if manifest else 'N/A'}\n"
        f"  Source: {source}  •  SHA: {sha}\n\n"
        f"[bright_green]📤 OUTPUT[/bright_green]\n  [bright_green]{output}[/bright_green]\n\n"
        "[bold white]🔒 ANALYSIS MODE[/bold white]\n"
        "  ✓ Offline  •  ✓ Deterministic  •  ✓ Explicit ATT&CK IDs only  •  ✓ No semantic inference\n\n"
        f"Expected: {expected}"
    )
    _panel(write, "✅ READY TO ANALYSE", body, "bright_green")


def _confirm_run(read: Reader, write: Writer) -> bool:
    write("[bright_cyan]1[/bright_cyan]  [bold white]▶ Run analysis[/bold white]")
    write("[white]2  × Cancel[/white]")
    return read("› ").strip().casefold() in {"1", "", "run"}


def _completion(write: Writer, title: str, metrics: list[tuple[str, object]], paths: list[Path]) -> None:
    lines = [f"[white]{label}[/white]\n  [bold bright_cyan]{value}[/bold bright_cyan]" for label, value in metrics]
    lines.append("[bold bright_green]📤 GENERATED FILE" + ("S" if len(paths) != 1 else "") + "[/bold bright_green]")
    lines.extend(f"[bold bright_green]{path}[/bold bright_green]" for path in paths)
    _panel(write, f"✅ {title}", "\n\n".join(lines), "bright_green")


def _optional_value(
    read: Reader,
    write: Writer,
    *,
    label: str,
    description: str,
    example: str,
    prompt: str | None = None,
) -> str | None:
    """Explain one optional value immediately before requesting it."""
    write(f"\n[bold white]{label}[/bold white]")
    write(f"[white]{description}[/white]")
    write(f"[cyan]Example: {example}[/cyan]")
    return read(f"{prompt or label} › ").strip() or None


def _report_workflow(read: Reader, write: Writer) -> None:
    guide = FEATURE_GUIDES["report"]
    selected_with_dialog = read is input and sys.stdin.isatty() and sys.stdout.isatty()
    if selected_with_dialog:
        _render_feature_guide(guide, write)
        write(
            "\n[bold bright_cyan]📄 REPORT SELECTION[/bold bright_cyan]\n"
            "[white]Use ↑/↓ to move and Space or Enter to select a report. "
            "Then use Tab to reach Run and Enter to confirm.[/white]"
        )
        selected = _select_report_files(DEFAULT_REPORT_DIRECTORY, write, multiple=False)
        report_path = selected[0] if selected else None
    else:
        if not _feature_guide(guide, read, write):
            return
        report_path = _path_input(
            read,
            write,
            title="📥 REPORT INPUT",
            prompt="Report path",
            kind="text report",
            default=DEFAULT_REPORT_DIRECTORY,
        )
    if report_path is None:
        return
    write("\n[bold magenta]⚙ OPTIONAL REPORT INFORMATION[/bold magenta]")
    write(
        "[white]These values describe the report in the workbook. Press Enter to leave any value unspecified.[/white]"
    )
    name = _optional_value(
        read,
        write,
        label="📝 Report name",
        description="Human-readable title shown in the workbook.",
        example="September 2026 intrusion investigation",
    )
    source = _optional_value(
        read,
        write,
        label="🏢 Source / publisher",
        description="Organization that published or supplied the report.",
        example="CERT-FR, Mandiant, or Internal SOC",
    )
    published_date = _optional_value(
        read,
        write,
        label="📅 Report date",
        description="Publication or internal report date in YYYY-MM-DD format.",
        example="2026-09-05",
        prompt="Report date (YYYY-MM-DD)",
    )
    tlp = _optional_value(
        read,
        write,
        label="🚦 TLP",
        description="Traffic Light Protocol marking: CLEAR, GREEN, AMBER, AMBER+STRICT, or RED.",
        example="AMBER",
        prompt="TLP",
    )
    confidence = _optional_value(
        read,
        write,
        label="🎯 Analyst confidence",
        description="Analyst-provided confidence wording; Odysafe does not calculate it.",
        example="High — confirmed by two internal sources",
    )
    output_value = _optional_value(
        read,
        write,
        label="📤 Output directory",
        description="Folder where the generated Excel workbook will be written.",
        example=str(DEFAULT_OUTPUT_DIRECTORY.resolve()),
        prompt=f"Output directory [{DEFAULT_OUTPUT_DIRECTORY.resolve()}]",
    )
    output = Path(output_value or DEFAULT_OUTPUT_DIRECTORY).expanduser().resolve()
    _attack_summary(write, str(report_path), output, guide.expected_result)
    if not _confirm_run(read, write):
        return
    result, output_path = _run_with_progress(
        "Building intelligence workbook",
        lambda: report.build(report_path, name, source, published_date, tlp, confidence, output, False, False),
        write,
    )
    _completion(
        write,
        "ANALYSIS COMPLETE",
        [
            ("📄 Report", result.report_metadata.filename),
            ("🌐 Unique IOCs", len(result.extraction_result.indicators)),
            ("🎯 ATT&CK techniques", len(result.extraction_result.ttps)),
            ("👤 Explicit actors", len(result.detected_actors)),
        ],
        [output_path],
    )


def _actor_workflow(read: Reader, write: Writer) -> None:
    guide = FEATURE_GUIDES["actor"]
    _render_feature_guide(guide, write)
    selected_with_dialog = read is input and sys.stdin.isatty() and sys.stdout.isatty()
    if selected_with_dialog:
        write(
            "\n[bold bright_cyan]👥 ACTOR SELECTION[/bold bright_cyan]\n"
            "[white]Use ↑/↓ to move and Space or Enter to select or clear actors. "
            "Then use Tab to reach Run and Enter to confirm.[/white]"
        )
        actor_ids = _select_actors(write)
        if not actor_ids:
            write("[yellow]← Actor selection cancelled.[/yellow]")
            return
        identifiers = ", ".join(actor_ids)
    else:
        identifiers = _actor_text_input(read, write)
        if not identifiers:
            return
        actor_ids = [value.strip() for value in identifiers.split(",") if value.strip()]
    _attack_summary(write, identifiers, DEFAULT_OUTPUT_DIRECTORY, guide.expected_result)
    if not selected_with_dialog and not _confirm_run(read, write):
        return
    result, output_path = _run_with_progress(
        "Building actor snapshot",
        lambda: actor.snapshot(actor_ids, DEFAULT_OUTPUT_DIRECTORY, False, True, True),
        write,
    )
    _completion(
        write,
        "ACTOR COMPARISON COMPLETE" if len(result.actors) > 1 else "ACTOR SNAPSHOT COMPLETE",
        [
            ("👥 Actors", len(result.actors)),
            ("🎯 Distinct techniques", len(result.techniques)),
            ("🧰 Software", len(result.software)),
            ("📅 Explicit campaigns", len(result.campaigns)),
        ],
        [output_path],
    )


def _actor_text_input(read: Reader, write: Writer) -> str:
    """Provide a deterministic fallback when a full-screen selector is unavailable."""
    write("[bright_cyan]1[/bright_cyan]  [bold white]▶ Continue to actor input[/bold white]")
    write("[white]2  ← Back[/white]")
    write("[cyan]Shortcut:[/cyan] enter one or several comma-separated actors now.")
    first_value = read("Continue, Back, or actor(s) › ").strip()
    if first_value.casefold() in {"2", "b", "back", "q", "quit"}:
        return ""
    identifiers = (
        read("Actor(s), comma-separated (example: APT29, Kimsuky) › ").strip()
        if first_value.casefold() in {"1", "", "c", "continue"}
        else first_value
    )
    if identifiers.casefold() in {"b", "back", "q", "quit"}:
        return ""
    actor_ids = [value.strip() for value in identifiers.split(",") if value.strip()]
    if not actor_ids:
        write("[bold bright_red]✗ AT LEAST ONE ACTOR IS REQUIRED[/bold bright_red]")
        return ""
    return identifiers


def _select_actors(write: Writer) -> list[str] | None:
    """Display every active ATT&CK group in a keyboard multi-select dialog."""
    manifest = load_manifest()
    if manifest is None or not manifest.bundle_path.is_file():
        write("[bold bright_red]✗ NO LOCAL MITRE ATT&CK DATA IS INSTALLED[/bold bright_red]")
        return None
    try:
        repository = AttackRepositoryImpl(manifest.bundle_path)
        groups = sorted(repository.get_groups(), key=lambda item: (item.name.casefold(), item.attack_id))
    except Exception as error:  # expected boundary: render a controlled interactive error
        write(f"[bold bright_red]✗ UNABLE TO LOAD ACTORS[/bold bright_red]  [white]{error}[/white]")
        return None
    values = [(group.attack_id, f"{group.name}  ({group.attack_id})") for group in groups]
    selected = checkboxlist_dialog(
        title="Odysafe — ATT&CK actor selection",
        text="Select one actor or several actors for comparison. Space or Enter toggles selection.",
        values=values,
        ok_text="Run",
        cancel_text="Back",
        style=ACTOR_SELECTOR_STYLE,
    ).run()
    return selected or None


def _select_sectors(write: Writer) -> list[str] | None:
    """Display configured sectors in the same keyboard selector as actors."""
    try:
        registry = SectorRegistry.load()
    except (OSError, ValueError) as error:
        write(f"[bold bright_red]✗ SECTOR CONFIGURATION UNAVAILABLE[/bold bright_red]  [white]{error}[/white]")
        return None
    values = [(item.id, f"{item.name}  ({item.id})") for item in registry.definitions]
    if not values:
        write("[bold bright_red]✗ NO CONFIGURED SECTORS[/bold bright_red]")
        return None
    selected = checkboxlist_dialog(
        title="Odysafe — sector selection",
        text="Select one or several sectors. Space or Enter toggles selection.",
        values=values,
        ok_text="Run",
        cancel_text="Back",
        style=ACTOR_SELECTOR_STYLE,
    ).run()
    return selected or None


def _select_report_files(directory: Path, write: Writer, *, multiple: bool = True) -> list[Path] | None:
    """Select one or several supported reports from an already chosen directory."""
    reports = sorted(
        (
            path
            for path in directory.rglob("*")
            if path.is_file() and path.suffix.casefold() in SUPPORTED_REPORT_SUFFIXES
        ),
        key=lambda path: path.name.casefold(),
    )
    if not reports:
        write(
            "[bold bright_red]✗ NO SUPPORTED REPORTS FOUND[/bold bright_red]  "
            "[white]The selected directory contains no TXT, HTML, PDF, or DOCX reports.[/white]"
        )
        return None
    values = [(str(path), str(path.relative_to(directory))) for path in reports]
    if multiple:
        selected = checkboxlist_dialog(
            title="Odysafe — report selection",
            text="Select one or several reports. Space or Enter toggles selection; Tab reaches Run.",
            values=values,
            ok_text="Run",
            cancel_text="Back",
            style=ACTOR_SELECTOR_STYLE,
        ).run()
        return [Path(value) for value in selected] if selected else None
    selected_one = radiolist_dialog(
        title="Odysafe — report selection",
        text="Select one report. Space or Enter selects; Tab reaches Run.",
        values=values,
        ok_text="Run",
        cancel_text="Back",
        style=ACTOR_SELECTOR_STYLE,
    ).run()
    return [Path(selected_one)] if selected_one else None


def _select_sigma_rules(directory: Path, write: Writer) -> list[Path] | None:
    """Display local Sigma YAML files in a keyboard multi-select dialog."""
    rules = sorted(
        (path for path in directory.rglob("*") if path.is_file() and path.suffix.casefold() in {".yml", ".yaml"}),
        key=lambda path: str(path.relative_to(directory)).casefold(),
    )
    if not rules:
        write(
            "[bold bright_red]✗ NO SIGMA RULES FOUND[/bold bright_red]  "
            "[white]Place YAML or YML rules in the configured Sigma folder.[/white]"
        )
        return None
    selected = checkboxlist_dialog(
        title="Odysafe — Sigma rule selection",
        text="Select one or several rules. Space or Enter toggles selection.",
        values=[(str(path), str(path.relative_to(directory))) for path in rules],
        ok_text="Run",
        cancel_text="Back",
        style=ACTOR_SELECTOR_STYLE,
    ).run()
    return [Path(value) for value in selected] if selected else None


def _sector_workflow(read: Reader, write: Writer) -> None:
    guide = FEATURE_GUIDES["sector"]
    selected_with_dialog = read is input and sys.stdin.isatty() and sys.stdout.isatty()
    if selected_with_dialog:
        _render_feature_guide(guide, write)
        write(
            "\n[bold bright_cyan]🏢 SECTOR SELECTION[/bold bright_cyan]\n"
            "[white]Use ↑/↓ to move and Space or Enter to select or clear sectors. "
            "Then use Tab to reach Run and Enter to confirm.[/white]"
        )
        selected = _select_sectors(write)
    else:
        if not _feature_guide(guide, read, write):
            return
        selected = _sector_selection(read, write)
    if not selected:
        return
    _attack_summary(write, ", ".join(selected), DEFAULT_OUTPUT_DIRECTORY, guide.expected_result)
    if not selected_with_dialog and not _confirm_run(read, write):
        return
    outcomes = sector.profile(selected, DEFAULT_OUTPUT_DIRECTORY, False, True)
    actor_count = sum(len(result.actors) for result, _path in outcomes)
    technique_count = sum(len(result.techniques) for result, _path in outcomes)
    critical_count = sum(
        item.priority_label.endswith("Critical") for result, _path in outcomes for item in result.risk_matrix
    )
    high_count = sum(item.priority_label.endswith("High") for result, _path in outcomes for item in result.risk_matrix)
    _completion(
        write,
        "SECTOR PROFILE COMPLETE",
        [
            ("🏢 Sectors", len(outcomes)),
            ("👥 ATT&CK groups", actor_count),
            ("🎯 Techniques", technique_count),
            ("🔴 Critical", critical_count),
            ("⚠ High priority", high_count),
        ],
        [path for _result, path in outcomes],
    )


def _aggregate_workflow(read: Reader, write: Writer) -> None:
    guide = FEATURE_GUIDES["aggregate"]
    selected_with_dialog = read is input and sys.stdin.isatty() and sys.stdout.isatty()
    if selected_with_dialog:
        _render_feature_guide(guide, write)
        write(
            "\n[bold bright_cyan]📄 REPORT SELECTION[/bold bright_cyan]\n"
            "[white]Use ↑/↓ to move and Space or Enter to select or clear reports. "
            "Then use Tab to reach Run and Enter to confirm.[/white]"
        )
        report_paths = _select_report_files(DEFAULT_REPORT_DIRECTORY, write)
        if not report_paths:
            write("[yellow]← Report selection cancelled.[/yellow]")
            return
        input_summary = "\n  ".join(str(path) for path in report_paths)
    else:
        if not _feature_guide(guide, read, write):
            return
        reports_path = _path_input(
            read,
            write,
            title="📥 REPORT DIRECTORY",
            prompt="Reports directory",
            kind="directory",
            default=DEFAULT_REPORT_DIRECTORY,
        )
        if reports_path is None:
            return
        report_paths = [reports_path]
        input_summary = str(reports_path)
    _attack_summary(write, input_summary, DEFAULT_OUTPUT_DIRECTORY, guide.expected_result)
    if not selected_with_dialog and not _confirm_run(read, write):
        return
    result, output_path = _run_with_progress(
        "Aggregating intelligence reports",
        lambda: aggregate_paths(report_paths, False, None, DEFAULT_OUTPUT_DIRECTORY, False),
        write,
    )
    _completion(
        write,
        "AGGREGATION COMPLETE",
        [
            ("📄 Unique reports", len(result.reports)),
            ("♻ Exact duplicates", len(result.duplicate_paths)),
            ("🌐 Unique IOCs", len(result.indicators)),
            ("🎯 Unique TTPs", len(result.techniques)),
            (
                "✅ Multi-source corroborations",
                sum(item.corroboration_status == "multi-source" for item in result.corroboration),
            ),
            (
                "⚠ False corroborations",
                sum(item.corroboration_status == "false" for item in result.corroboration),
            ),
        ],
        [output_path],
    )


def _sigma_workflow(read: Reader, write: Writer) -> None:
    guide = FEATURE_GUIDES["sigma"]
    selected_with_dialog = read is input and sys.stdin.isatty() and sys.stdout.isatty()
    if selected_with_dialog:
        _render_feature_guide(guide, write)
        write(
            "\n[bold bright_cyan]📄 REPORT SELECTION[/bold bright_cyan]\n"
            "[white]Use ↑/↓ to move and Space or Enter to select a report. "
            "Then use Tab to reach Run and Enter to confirm.[/white]"
        )
        selected = _select_report_files(DEFAULT_REPORT_DIRECTORY, write, multiple=False)
        report_path = selected[0] if selected else None
    else:
        if not _feature_guide(guide, read, write):
            return
        report_path = _path_input(
            read, write, title="📄 CTI REPORT", prompt="Report", kind="text report", default=DEFAULT_REPORT_DIRECTORY
        )
    if report_path is None:
        return
    sigma_source: Path | list[Path]
    if selected_with_dialog:
        write(
            "\n[bold bright_cyan]🛡 SIGMA RULE SELECTION[/bold bright_cyan]\n"
            "[white]Use ↑/↓ to move and Space or Enter to select or clear rules. "
            "Then use Tab to reach Run and Enter to confirm.[/white]"
        )
        selected_rules = _select_sigma_rules(DEFAULT_SIGMA_DIRECTORY, write)
        if not selected_rules:
            return
        sigma_source = selected_rules
        sigma_summary = "\n  ".join(str(path) for path in selected_rules)
    else:
        sigma_path = _path_input(
            read,
            write,
            title="📁 SIGMA RULE DIRECTORY",
            prompt="Sigma directory",
            kind="directory",
            default=DEFAULT_SIGMA_DIRECTORY,
        )
        if sigma_path is None:
            return
        sigma_source = sigma_path
        sigma_summary = str(sigma_path)
    _attack_summary(write, f"{report_path}\n  {sigma_summary}", DEFAULT_OUTPUT_DIRECTORY, guide.expected_result)
    if not selected_with_dialog and not _confirm_run(read, write):
        return
    result, output_path = _run_with_progress(
        "Analyzing Sigma coverage",
        lambda: coverage.sigma_paths(report_path, sigma_source, DEFAULT_OUTPUT_DIRECTORY, False, False),
        write,
    )
    _completion(
        write,
        "SIGMA COVERAGE COMPLETE",
        [
            ("🎯 ATT&CK techniques analysed", len(result.coverage)),
            ("✅ Exact coverage", result.exact_count),
            ("⚠ Partial coverage", result.partial_count),
            ("❌ Not covered", result.none_count),
            (
                "📊 Exact coverage",
                f"{result.exact_count / len(result.coverage) * 100:.1f}%" if result.coverage else "0.0%",
            ),
        ],
        [output_path],
    )


def _analysis_menu(read: Reader, write: Writer) -> None:
    menu = (
        (
            "1",
            "📄",
            "REPORT WORKBOOK",
            "Extract explicit IOCs and ATT&CK IDs from one report",
            "local TXT, HTML, PDF, or DOCX report",
            "dashboard with IOCs, TTPs, detections, mitigations, and provenance",
        ),
        (
            "2",
            "👤",
            "ACTOR SNAPSHOT",
            "Explore direct ATT&CK knowledge for one or several groups",
            "ATT&CK group checklist; Space or Enter selects actors",
            "actor intelligence workbook or multi-actor comparison",
        ),
        (
            "3",
            "🏢",
            "SECTOR PROFILE",
            "Build local sector priorities from configured actor mappings",
            "configured sector checklist; Space or Enter selects sectors",
            "one threat-profile workbook per selected sector",
        ),
        (
            "4",
            "🗂",
            "AGGREGATE REPORTS",
            "Find duplicates and repeated evidence across reports",
            "report checklist; Space or Enter selects one or several files",
            "combined workbook with IOCs, TTPs, and corroboration",
        ),
        (
            "5",
            "🛡",
            "SIGMA COVERAGE",
            "Compare explicit report TTPs with local Sigma ATT&CK tags",
            "one report plus one or several Sigma rules selected from checklists",
            "coverage workbook showing exact, partial, and missing detections",
        ),
    )
    workflows = {
        "1": _report_workflow,
        "2": _actor_workflow,
        "3": _sector_workflow,
        "4": _aggregate_workflow,
        "5": _sigma_workflow,
    }
    while True:
        _panel(
            write,
            "✦  ANALYSIS STUDIO",
            "\n[bold white]Transform local CTI into ATT&CK intelligence[/bold white]\n",
            centered=True,
        )
        _render_default_input_locations(write)
        for number, icon, title, description, input_value, output_value in menu:
            write(f"\n[bright_cyan][{number}][/bright_cyan]  {icon}  [bold white]{title}[/bold white]")
            write(f"     [white]{description}[/white]")
            write(f"     [yellow]Input:[/yellow] [cyan]{input_value}[/cyan]")
            write(f"     [bright_green]Output:[/bright_green] [green]{output_value}[/green]")
        write("\n[white][6]  ← BACK[/white]")
        choice = read("\033[1;36m›\033[0m ").strip()
        if choice == "6":
            return
        if choice in workflows:
            workflows[choice](read, write)
        else:
            write("[bold bright_red]✗ INVALID CHOICE[/bold bright_red]")


def _render_default_input_locations(write: Writer) -> None:
    """Show stable default input paths and a concise live inventory."""
    report_directory = DEFAULT_REPORT_DIRECTORY.resolve()
    sigma_directory = DEFAULT_SIGMA_DIRECTORY.resolve()
    reports = (
        sorted(
            item.name
            for item in report_directory.iterdir()
            if item.is_file() and item.suffix.casefold() in SUPPORTED_REPORT_SUFFIXES
        )
        if report_directory.is_dir()
        else []
    )
    sigma_rules = (
        sorted(
            item.name
            for item in sigma_directory.iterdir()
            if item.is_file() and item.suffix.casefold() in {".yml", ".yaml"}
        )
        if sigma_directory.is_dir()
        else []
    )

    def inventory(files: list[str], empty_message: str) -> str:
        if not files:
            return f"[yellow]⚠ {empty_message}[/yellow]"
        preview = ", ".join(files[:3])
        remainder = f" + {len(files) - 3} more" if len(files) > 3 else ""
        return f"[green]✓ {len(files)} available[/green]  [cyan]{preview}{remainder}[/cyan]"

    body = (
        "[bold white]📄 REPORTS[/bold white]  [white]Used by Report, Aggregate, and Sigma Coverage[/white]\n"
        f"  [bold bright_cyan]{report_directory}[/bold bright_cyan]\n"
        "  [white]Place TXT, HTML, PDF, or DOCX reports here.[/white]\n"
        f"  {inventory(reports, 'NO SUPPORTED REPORTS FOUND')}\n\n"
        "[bold white]🛡 SIGMA RULES[/bold white]  [white]Used by Sigma Coverage[/white]\n"
        f"  [bold bright_cyan]{sigma_directory}[/bold bright_cyan]\n"
        "  [white]Place YAML or YML Sigma rules here.[/white]\n"
        f"  {inventory(sigma_rules, 'NO SIGMA RULES FOUND')}\n\n"
        "[blue]ℹ Guided mode lists these files for keyboard selection. Direct commands accept other paths.[/blue]"
    )
    _panel(write, "📥 DEFAULT INPUT LOCATIONS", body, "cyan")


def run_interactive(read: Reader = input, write: Writer = _styled_write) -> int:
    """Run the interactive menu until the user quits or closes input."""
    _header(write)
    while True:
        _panel(
            write,
            "✦  ACTIONS",
            "[bold white]Choose what you want to do.[/bold white]\n\n"
            "[white]Network access is always announced and requires confirmation.[/white]",
            "magenta",
        )
        write(
            "\n[bright_cyan][1][/bright_cyan]  [bold white]🔎  INSPECT MITRE DATA[/bold white]\n"
            "     [white]View installed snapshots and compatibility details.[/white]"
        )
        write(
            "\n[bright_cyan][2][/bright_cyan]  [bold white]↻  UPDATE MITRE DATA[/bold white]\n"
            "     [white]Download and install the latest official dataset.[/white]"
        )
        write(
            "\n[bright_cyan][3][/bright_cyan]  [bold white]↓  INSTALL A MITRE RELEASE[/bold white]\n"
            "     [white]Install a specific version, such as [/white][cyan]19.2[/cyan][white].[/white]"
        )
        write(
            "\n[bright_cyan][4][/bright_cyan]  [bold white]✦  RUN ANALYSIS / GENERATION[/bold white]\n"
            "     [white]Create CTI intelligence workbooks and Navigator layers.[/white]"
        )
        write(
            "\n[bright_cyan][5][/bright_cyan]  [bold white]♥  CHECK INSTALLATION HEALTH[/bold white]\n"
            "     [white]Verify the local installation safely offline.[/white]"
        )
        write("\n[white][6]  ×  QUIT[/white]\n")
        try:
            choice = read("\033[1;36m›\033[0m ").strip()
            if choice == "1":
                _run_with_progress("Inspecting local ATT&CK data", partial(_inspect, write), write)
            elif choice == "2":
                if _confirm("This operation accesses the network. Continue?", read, write):
                    data.update()
            elif choice == "3":
                release = normalize_release(read("Release (example: 19.2): "))
                if _confirm("This operation accesses the network. Continue?", read, write):
                    _install_release(release)
            elif choice == "4":
                _analysis_menu(read, write)
            elif choice == "5":
                _run_with_progress("Checking installation health", partial(run_doctor, _console), write)
            elif choice == "6":
                return 0
            else:
                write("Invalid choice.")
        except (EOFError, KeyboardInterrupt):
            write("\nGoodbye.")
            return 0
        except (typer.Exit, SystemExit) as error:
            code = getattr(error, "exit_code", getattr(error, "code", 1))
            if code not in (None, 0):
                write("The operation could not be completed.")
        except Exception as error:
            write(f"Error: {error}")
        write("")
