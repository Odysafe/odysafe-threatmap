"""Tests for centralized Excel theme construction."""

from pathlib import Path

from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook


def test_theme_exposes_semantic_colors_and_formats(tmp_path: Path) -> None:
    """One theme provides all required reusable formats."""
    filename = tmp_path / "theme.xlsx"
    workbook = ExcelWorkbook(filename)

    assert set(workbook.theme.colors) >= {"success", "warning", "critical", "info", "neutral"}
    assert workbook.theme.header_format is not None
    assert workbook.theme.date_format is not None
    assert workbook.theme.url_format is not None
    workbook.close()
