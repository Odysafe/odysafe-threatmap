"""Technique matrix worksheet for Module B."""

from odysafe_threatmap.application.actor_snapshot import ActorSnapshotResult
from odysafe_threatmap.domain.models import NOT_AVAILABLE
from odysafe_threatmap.exporters.excel.tables import ExcelColumn, create_excel_table
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook


def write_ttps_sheet_b(workbook: ExcelWorkbook, snapshot_result: ActorSnapshotResult) -> None:
    """Write ATT&CK techniques and an actor-presence matrix."""
    sheet = workbook.add_sheet("TTPs")
    rows = []
    for technique in snapshot_result.techniques:
        row = {
            "attack_id": technique.attack_id,
            "name": technique.name,
            "tactics": ", ".join(technique.tactics) or NOT_AVAILABLE,
            "platforms": ", ".join(technique.platforms) or NOT_AVAILABLE,
            "description": technique.description,
            "popularity": snapshot_result.technique_popularity.get(technique.stix_id, 0),
        }
        for actor in snapshot_result.actors:
            actor_ids = {item.stix_id for item in snapshot_result.actor_techniques[actor.stix_id]}
            row[actor.stix_id] = "✓" if technique.stix_id in actor_ids else ""
        rows.append(row)
    columns = [
        ExcelColumn("attack_id", "Technique ID"),
        ExcelColumn("name", "Name"),
        ExcelColumn("tactics", "Tactics", 25),
        ExcelColumn("platforms", "Platforms", 25),
        ExcelColumn("description", "Description", 45),
        ExcelColumn("popularity", "Groups using technique"),
    ] + [ExcelColumn(actor.stix_id, actor.name, 18) for actor in snapshot_result.actors]
    _start_row, _start_col, end_row, _end_col = create_excel_table(workbook, sheet, rows, 0, 0, columns)
    sheet.worksheet.set_zoom(75 if len(snapshot_result.actors) > 4 else 85)
    sheet.worksheet.freeze_panes(1, 0)
    for row_index in range(1, end_row + 1):
        sheet.worksheet.set_row(row_index, 72)
