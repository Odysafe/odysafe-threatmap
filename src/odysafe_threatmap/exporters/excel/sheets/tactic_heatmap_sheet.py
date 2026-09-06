"""Tactic heatmap worksheet for Module B."""

from odysafe_threatmap.application.actor_snapshot import ActorSnapshotResult
from odysafe_threatmap.exporters.excel.tables import ExcelColumn, create_excel_table
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook


def write_tactic_heatmap_sheet(workbook: ExcelWorkbook, snapshot_result: ActorSnapshotResult) -> None:
    """Write tactic coverage with data bars for visual comparison."""
    sheet = workbook.add_sheet("Heatmap tactiques")
    tactics: dict[str, list[str]] = {}
    for technique in snapshot_result.techniques:
        for tactic in technique.tactics:
            tactics.setdefault(tactic, []).append(technique.attack_id)
    rows = [
        {"tactic": tactic, "count": len(ids), "ids": ", ".join(sorted(ids))} for tactic, ids in sorted(tactics.items())
    ]
    create_excel_table(
        workbook,
        sheet,
        rows,
        0,
        0,
        [
            ExcelColumn("tactic", "Tactic"),
            ExcelColumn("count", "Technique count"),
            ExcelColumn("ids", "Technique IDs", 45),
        ],
    )
    if rows:
        sheet.worksheet.conditional_format(1, 1, len(rows), 1, {"type": "data_bar", "bar_color": "#2F75B5"})
