"""Non-attribution TTP overlap worksheet."""

from collections.abc import Sequence
from typing import Any

from odysafe_threatmap.exporters.excel.display_text import format_list
from odysafe_threatmap.exporters.excel.sheets.common import write_no_data_banner
from odysafe_threatmap.exporters.excel.tables import ExcelColumn, create_excel_table
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook

OVERLAP_DISCLAIMER = "Corrélation par recouvrement de TTPs — ne constitue pas une attribution."


def write_associated_groups_sheet(workbook: ExcelWorkbook, overlaps: Sequence[Any]) -> None:
    """Write calculated group overlap with an explicit non-attribution disclaimer."""
    sheet = workbook.add_sheet("Groupes associés")
    workbook.write_subtitle(sheet, 0, 0, OVERLAP_DISCLAIMER)
    ordered = sorted(
        overlaps, key=lambda item: (-len(item.common_technique_ids), -item.overlap_percent, item.actor.name)
    )
    report_ttps = max(
        (len(item.common_technique_ids) / (item.overlap_percent / 100) for item in ordered if item.overlap_percent),
        default=0,
    )
    if report_ttps < 3 and ordered:
        workbook.write_subtitle(
            sheet, 1, 0, "⚠ Faible nombre de TTPs dans le rapport : le recouvrement est peu discriminant."
        )
    rows = [
        {
            "rank": rank,
            "group": item.actor.name,
            "common": len(item.common_technique_ids),
            "report_ttps": round(report_ttps),
            "percentage": item.overlap_percent / 100,
            "techniques": format_list(item.common_technique_ids),
            "sectors": format_list(item.actor.sectors),
        }
        for rank, item in enumerate(ordered, start=1)
    ]
    if not rows:
        write_no_data_banner(sheet, 2)
    create_excel_table(
        workbook,
        sheet,
        rows,
        5 if not rows else 3,
        0,
        [
            ExcelColumn("rank", "Rang"),
            ExcelColumn("group", "Groupe", 32),
            ExcelColumn("common", "TTPs communes"),
            ExcelColumn("report_ttps", "TTPs du rapport"),
            ExcelColumn("percentage", "Recouvrement"),
            ExcelColumn("techniques", "Techniques communes", 40),
            ExcelColumn("sectors", "Secteurs — mapping local", 32),
        ],
    )
