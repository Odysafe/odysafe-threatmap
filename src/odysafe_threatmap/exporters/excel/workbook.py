"""Secure, reusable XlsxWriter workbook wrapper."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import xlsxwriter

from odysafe_threatmap.config.loader import compute_embedded_config_hash
from odysafe_threatmap.exporters.excel.security import escape_excel_value
from odysafe_threatmap.exporters.excel.theme import ExcelTheme
from odysafe_threatmap.storage.manifest import generate_manifest


@dataclass(slots=True)
class WorksheetWrapper:
    """A minimal exporter-facing wrapper around an XlsxWriter worksheet."""

    worksheet: Any
    name: str

    def __getattr__(self, attribute: str) -> Any:
        """Delegate supported worksheet operations to XlsxWriter."""
        return getattr(self.worksheet, attribute)


class ExcelWorkbook:
    """Create secure workbooks while keeping XlsxWriter out of domain code."""

    def __init__(self, filename: Path, theme: ExcelTheme | None = None, metadata: dict[str, Any] | None = None) -> None:
        """Create an XlsxWriter workbook with formula conversion disabled."""
        self.filename = Path(filename)
        self.filename.parent.mkdir(parents=True, exist_ok=True)
        self.xlsxwriter_workbook = xlsxwriter.Workbook(
            str(self.filename), {"strings_to_formulas": False, "strings_to_urls": False}
        )
        self.theme = theme or ExcelTheme(self.xlsxwriter_workbook)
        self._metadata = dict(metadata or {})
        parameters = dict(self._metadata.get("parameters", {}))
        parameters.setdefault("config_hash_or_version", compute_embedded_config_hash())
        self._metadata["parameters"] = parameters
        self._closed = False

    def add_sheet(self, name: str, hidden: bool = False) -> WorksheetWrapper:
        """Add a worksheet and optionally hide it from normal workbook views."""
        worksheet = self.xlsxwriter_workbook.add_worksheet(name)
        if hidden:
            worksheet.hide()
        return WorksheetWrapper(worksheet, name)

    def escape_value(self, value: Any) -> Any:
        """Return an Excel-safe value."""
        return escape_excel_value(value)

    def write_kpi(self, sheet: WorksheetWrapper, row: int, col: int, value: Any, label: str) -> None:
        """Write a standardized KPI card."""
        self.theme.apply_kpi(sheet, row, col, self.escape_value(value), label)

    def write_title(self, sheet: WorksheetWrapper, row: int, col: int, title: str) -> None:
        """Write a standardized title."""
        sheet.worksheet.write(row, col, self.escape_value(title), self.theme.title_format)

    def write_subtitle(self, sheet: WorksheetWrapper, row: int, col: int, subtitle: str) -> None:
        """Write a standardized subtitle."""
        sheet.worksheet.write(row, col, self.escape_value(subtitle), self.theme.subtitle_format)

    def set_manifest_metadata(self, metadata: dict[str, Any]) -> None:
        """Replace metadata emitted with the workbook manifest."""
        self._metadata = dict(metadata)

    def close(self) -> None:
        """Close the workbook and emit its adjacent technical manifest."""
        if self._closed:
            return
        self.xlsxwriter_workbook.close()
        generate_manifest(self.filename, self._metadata)
        self._closed = True

    def __enter__(self) -> "ExcelWorkbook":
        """Return this workbook for context manager use."""
        return self

    def __exit__(self, exception_type: Any, exception: Any, traceback: Any) -> None:
        """Close the workbook at context exit."""
        self.close()
