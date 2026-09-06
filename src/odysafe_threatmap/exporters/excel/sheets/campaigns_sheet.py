"""Campaign worksheet for Module B."""

from odysafe_threatmap.application.actor_snapshot import ActorSnapshotResult
from odysafe_threatmap.domain.models import NOT_AVAILABLE
from odysafe_threatmap.exporters.excel.display_text import format_list, truncate_display_text
from odysafe_threatmap.exporters.excel.sheets.common import write_no_data_banner
from odysafe_threatmap.exporters.excel.tables import ExcelColumn, create_excel_table
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook


def write_campaigns_sheet(workbook: ExcelWorkbook, snapshot_result: ActorSnapshotResult) -> None:
    """Write structured ATT&CK campaign records when requested."""
    sheet = workbook.add_sheet("Campagnes")
    rows = [
        {
            "attack_id": item.attack_id,
            "name": item.name,
            "first_seen": item.first_seen or NOT_AVAILABLE,
            "last_seen": item.last_seen or NOT_AVAILABLE,
            "description": truncate_display_text(item.description, 350),
            "techniques": format_list(item.techniques),
            "software": format_list(item.software),
            "url": item.attack_url,
        }
        for item in snapshot_result.campaigns
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
            ExcelColumn("attack_id", "ATT&CK ID"),
            ExcelColumn("name", "Name"),
            ExcelColumn("first_seen", "First seen"),
            ExcelColumn("last_seen", "Last seen"),
            ExcelColumn("description", "Description", 45),
            ExcelColumn("techniques", "Techniques", 25),
            ExcelColumn("software", "Software", 25),
            ExcelColumn("url", "ATT&CK URL", 45),
        ],
    )
    sheet.worksheet.set_zoom(80)
    sheet.worksheet.freeze_panes(1 if rows else 3, 0)
    for row_index in range(1 if rows else 3, end_row + 1):
        sheet.worksheet.set_row(row_index, 72)
