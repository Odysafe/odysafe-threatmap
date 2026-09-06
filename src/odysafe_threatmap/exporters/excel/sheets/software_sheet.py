"""Software worksheet for Module B."""

from odysafe_threatmap.application.actor_snapshot import ActorSnapshotResult
from odysafe_threatmap.domain.models import NOT_AVAILABLE
from odysafe_threatmap.exporters.excel.sheets.common import write_no_data_banner
from odysafe_threatmap.exporters.excel.tables import ExcelColumn, create_excel_table
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook


def write_software_sheet(workbook: ExcelWorkbook, snapshot_result: ActorSnapshotResult) -> None:
    """Write malware and tool records linked to resolved actors."""
    sheet = workbook.add_sheet("Logiciels - Malwares")
    rows = [
        {
            "name": item.name,
            "attack_id": item.attack_id,
            "type": item.type,
            "platforms": ", ".join(item.platforms) or NOT_AVAILABLE,
            "description": item.description,
            "techniques": ", ".join(item.techniques) or NOT_AVAILABLE,
            "groups": ", ".join(item.other_groups) or NOT_AVAILABLE,
            "url": item.attack_url,
        }
        for item in snapshot_result.software
    ]
    if not rows:
        write_no_data_banner(sheet, 0)
    _start_row, _start_col, end_row, _end_col = create_excel_table(
        workbook,
        sheet,
        rows,
        2 if not rows else 0,
        0,
        [
            ExcelColumn("name", "Name"),
            ExcelColumn("attack_id", "ATT&CK ID"),
            ExcelColumn("type", "Type"),
            ExcelColumn("platforms", "Platforms", 25),
            ExcelColumn("description", "Description", 45),
            ExcelColumn("techniques", "Techniques", 25),
            ExcelColumn("groups", "Other groups", 25),
            ExcelColumn("url", "ATT&CK URL", 45),
        ],
    )
    sheet.worksheet.set_zoom(80)
    sheet.worksheet.freeze_panes(1 if rows else 3, 0)
    for row_index in range(1 if rows else 3, end_row + 1):
        sheet.worksheet.set_row(row_index, 72)
