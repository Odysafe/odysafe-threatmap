"""Smoke tests for the command-line skeleton."""

from typer.testing import CliRunner

from odysafe_threatmap import __version__
from odysafe_threatmap.cli.app import app


def test_help_is_available() -> None:
    """The CLI skeleton exposes a successful help page."""
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "operational cyber threat intelligence" in result.output


def test_version_is_available() -> None:
    """The packaged CLI exposes the canonical application version."""
    result = CliRunner().invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == __version__
