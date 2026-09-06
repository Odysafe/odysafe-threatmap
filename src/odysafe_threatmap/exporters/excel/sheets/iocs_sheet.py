"""Detailed IOC worksheet."""

from odysafe_threatmap.domain.models import ExtractedIndicator
from odysafe_threatmap.exporters.excel.display_text import format_ioc_type, format_yes_no
from odysafe_threatmap.exporters.excel.sheets.common import write_no_data_banner
from odysafe_threatmap.exporters.excel.tables import ExcelColumn, create_excel_table
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook


def write_iocs_sheet(workbook: ExcelWorkbook, indicators: list[ExtractedIndicator]) -> None:
    """Write one row per deduplicated extracted indicator."""
    sheet = workbook.add_sheet("IOCs")
    rows = [
        {
            "type": format_ioc_type(item.type),
            "normalized": item.normalized_value,
            "raw": item.raw_value,
            "defanged": format_yes_no(item.defanged),
            "occurrences": item.occurrences,
            "first_line": item.first_line,
            "lines": ", ".join(map(str, item.lines)),
            "first_offset": item.first_offset,
            "engine": item.extraction_engine,
        }
        for item in indicators
    ]
    if not rows:
        write_no_data_banner(sheet, 0)
    create_excel_table(
        workbook,
        sheet,
        rows,
        2 if not rows else 0,
        0,
        [
            ExcelColumn("type", "Type"),
            ExcelColumn("normalized", "Valeur normalisée", 40),
            ExcelColumn("raw", "Exemple brut", 40),
            ExcelColumn("defanged", "Defang observé"),
            ExcelColumn("occurrences", "Occurrences"),
            ExcelColumn("first_line", "Première ligne"),
            ExcelColumn("lines", "Lignes"),
            ExcelColumn("first_offset", "Premier offset"),
            ExcelColumn("engine", "Extracteur"),
        ],
    )
