"""Actor profile worksheet for Module B."""

from odysafe_threatmap.application.actor_snapshot import ActorSnapshotResult
from odysafe_threatmap.domain.models import NOT_AVAILABLE
from odysafe_threatmap.exporters.excel.display_text import format_list, truncate_display_text
from odysafe_threatmap.exporters.excel.tables import ExcelColumn, create_excel_table
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook


def _joined(values: tuple[str, ...]) -> str:
    return ", ".join(values) if values else NOT_AVAILABLE


def write_profile_sheet(workbook: ExcelWorkbook, snapshot_result: ActorSnapshotResult) -> None:
    """Write one structured ATT&CK profile row per resolved actor."""
    sheet = workbook.add_sheet("Profil")
    rows = [
        {
            "attack_id": actor.attack_id,
            "name": actor.name,
            "aliases": format_list(actor.aliases, 8),
            "description": truncate_display_text(actor.description, 450),
            "first_seen": actor.first_seen,
            "last_seen": actor.last_seen,
            "origin": actor.origin,
            "primary_motivation": actor.primary_motivation,
            "secondary_motivations": _joined(actor.secondary_motivations),
            "resource_level": actor.resource_level,
            "sectors": _joined(actor.sectors),
            "regions": _joined(actor.regions),
            "ttps": len(snapshot_result.actor_techniques[actor.stix_id]),
            "software": len(snapshot_result.actor_software[actor.stix_id]),
            "campaigns": len(snapshot_result.actor_campaigns[actor.stix_id]),
            "url": actor.attack_url,
        }
        for actor in snapshot_result.actors
    ]
    _start_row, _start_col, end_row, _end_col = create_excel_table(
        workbook,
        sheet,
        rows,
        0,
        0,
        [
            ExcelColumn("attack_id", "ATT&CK ID"),
            ExcelColumn("name", "Name"),
            ExcelColumn("aliases", "Aliases", 28),
            ExcelColumn("description", "Description", 45),
            ExcelColumn("first_seen", "First seen"),
            ExcelColumn("last_seen", "Last seen"),
            ExcelColumn("origin", "Origin"),
            ExcelColumn("primary_motivation", "Primary motivation", 22),
            ExcelColumn("secondary_motivations", "Secondary motivations", 25),
            ExcelColumn("resource_level", "Resource level"),
            ExcelColumn("sectors", "Sectors", 25),
            ExcelColumn("regions", "Regions", 25),
            ExcelColumn("ttps", "TTPs"),
            ExcelColumn("software", "Software"),
            ExcelColumn("campaigns", "Campaigns"),
            ExcelColumn("url", "ATT&CK URL", 45),
        ],
    )
    sheet.worksheet.set_zoom(80)
    sheet.worksheet.freeze_panes(1, 0)
    for row_index in range(1, end_row + 1):
        sheet.worksheet.set_row(row_index, 72)
