"""ATT&CK mitigation worksheet."""

from odysafe_threatmap.domain.models import AttackTechnique
from odysafe_threatmap.exporters.excel.display_text import truncate_display_text
from odysafe_threatmap.exporters.excel.sheets.common import write_no_data_banner
from odysafe_threatmap.exporters.excel.tables import ExcelColumn, create_excel_table
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook


def write_mitigations_sheet(workbook: ExcelWorkbook, ttps: list[AttackTechnique]) -> None:
    """Write one mitigation row for each enriched technique."""
    sheet = workbook.add_sheet("Mitigations")
    rows = [
        {
            "technique_id": item.attack_id,
            "technique": item.name,
            "mitigation_id": mitigation.attack_id,
            "mitigation": mitigation.name,
            "description": truncate_display_text(mitigation.description, 300),
        }
        for item in ttps
        for mitigation in item.mitigations
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
            ExcelColumn("technique_id", "ID technique"),
            ExcelColumn("technique", "Technique", 32),
            ExcelColumn("mitigation_id", "ID mitigation"),
            ExcelColumn("mitigation", "Mitigation", 32),
            ExcelColumn("description", "Description ATT&CK courte", 45),
        ],
    )
