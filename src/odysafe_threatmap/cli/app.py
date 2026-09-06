"""Top-level command-line application."""

from typing import Annotated

import typer

from odysafe_threatmap import __version__
from odysafe_threatmap.cli.commands.actor import app as actor_app
from odysafe_threatmap.cli.commands.aggregate import aggregate
from odysafe_threatmap.cli.commands.coverage import app as coverage_app
from odysafe_threatmap.cli.commands.data import app as data_app
from odysafe_threatmap.cli.commands.doctor import doctor
from odysafe_threatmap.cli.commands.navigator import app as navigator_app
from odysafe_threatmap.cli.commands.report import app as report_app
from odysafe_threatmap.cli.commands.sector import app as sector_app
from odysafe_threatmap.cli.interactive import run_interactive

app = typer.Typer(
    help="Offline, deterministic tools for operational cyber threat intelligence.",
    no_args_is_help=False,
    invoke_without_command=True,
)
app.add_typer(data_app, name="data")
app.add_typer(coverage_app, name="coverage")
app.add_typer(actor_app, name="actor")
app.command()(aggregate)
app.add_typer(report_app, name="report")
app.add_typer(navigator_app, name="navigator")
app.add_typer(sector_app, name="sector")
app.command()(doctor)


@app.callback()
def root(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option("--version", help="Show the application version and exit.", is_eager=True),
    ] = False,
) -> None:
    """Run odysafe-threatmap commands."""
    if version:
        typer.echo(__version__)
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        raise typer.Exit(run_interactive())


@app.command("interactive")
def interactive() -> None:
    """Open the interactive terminal menu."""
    raise typer.Exit(run_interactive())


@app.command("cti")
def cti() -> None:
    """Open the interactive Analysis Studio."""
    raise typer.Exit(run_interactive())


def main() -> None:
    """Run the command-line application."""
    app()
