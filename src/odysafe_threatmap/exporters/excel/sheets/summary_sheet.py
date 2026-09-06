"""Reusable summary worksheet composition."""

from collections.abc import Mapping, Sequence
from typing import Any

from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook, WorksheetWrapper


def write_summary_sheet(workbook: ExcelWorkbook, kpis: Mapping[str, Any], charts: Sequence[Any]) -> WorksheetWrapper:
    """Create a summary sheet with KPI cards and up to four chart objects."""
    if len(charts) > 4:
        raise ValueError("A summary sheet supports at most four charts.")
    sheet = workbook.add_sheet("Synthèse")
    workbook.write_title(sheet, 0, 0, "ODYSAFE THREATMAP")
    workbook.write_subtitle(sheet, 1, 0, "Synthèse de l'analyse déterministe hors ligne")
    for index, (label, value) in enumerate(kpis.items()):
        workbook.write_kpi(sheet, 2, index * 2, value, label)
    for index, chart in enumerate(chart for chart in charts if chart is not None):
        row = 6 + (index // 2) * 18
        col = (index % 2) * 9
        sheet.worksheet.insert_chart(row, col, chart)
    return sheet
