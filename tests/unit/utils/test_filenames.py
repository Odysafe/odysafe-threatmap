"""Tests for output filename helpers."""

from pathlib import Path

from odysafe_threatmap.utils.filenames import ensure_output_dir, generate_output_filename, sanitize_filename


def test_filename_helpers_sanitize_and_avoid_collisions(tmp_path: Path) -> None:
    """Output names are safe and gain a timestamp after an existing collision."""
    output_directory = ensure_output_dir(tmp_path / "output")
    filename = generate_output_filename("report", "CISA / advisory", "xlsx")
    (output_directory / filename).touch()

    collision_name = generate_output_filename("report", "CISA / advisory", ".xlsx", output_directory)
    assert sanitize_filename(" CISA / advisory ") == "CISA_advisory"
    assert filename == "report_CISA_advisory.xlsx"
    assert collision_name.startswith("report_CISA_advisory_")
