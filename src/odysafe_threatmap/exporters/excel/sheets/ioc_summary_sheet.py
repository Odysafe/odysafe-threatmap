"""IOC summary worksheet."""

from collections import defaultdict

from odysafe_threatmap.domain.models import ExtractedIndicator
from odysafe_threatmap.exporters.excel.display_text import format_ioc_type
from odysafe_threatmap.exporters.excel.sheets.common import write_no_data_banner
from odysafe_threatmap.exporters.excel.tables import ExcelColumn, create_excel_table
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook


def write_ioc_summary_sheet(workbook: ExcelWorkbook, indicators: list[ExtractedIndicator]) -> None:
    """Write indicator counts grouped by type."""
    sheet = workbook.add_sheet("Résumé IOCs")
    grouped: defaultdict[str, list[ExtractedIndicator]] = defaultdict(list)
    for indicator in indicators:
        grouped[indicator.type].append(indicator)
    rows = [
        {
            "type": format_ioc_type(name),
            "unique": len(values),
            "occurrences": sum(item.occurrences for item in values),
            "example": values[0].normalized_value,
        }
        for name, values in sorted(grouped.items())
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
            ExcelColumn("unique", "Nb uniques"),
            ExcelColumn("occurrences", "Occurrences"),
            ExcelColumn("example", "Exemple", 40),
        ],
    )
