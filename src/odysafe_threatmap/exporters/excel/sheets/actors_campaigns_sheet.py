"""Explicitly detected actor and campaign worksheet."""

from odysafe_threatmap.domain.models import ActorRecord
from odysafe_threatmap.exporters.excel.display_text import format_list, truncate_display_text
from odysafe_threatmap.exporters.excel.sheets.common import write_no_data_banner
from odysafe_threatmap.exporters.excel.tables import ExcelColumn, create_excel_table
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook


def write_actors_campaigns_sheet(workbook: ExcelWorkbook, detected_actors: list[ActorRecord]) -> None:
    """Write only groups explicitly identified in the report text."""
    sheet = workbook.add_sheet("Acteurs - Campagnes")
    rows = [
        {
            "id": actor.attack_id,
            "name": actor.name,
            "aliases": format_list(actor.aliases, 8),
            "type": "Groupe",
            "description": truncate_display_text(actor.description, 450),
            "url": actor.attack_url,
        }
        for actor in detected_actors
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
            ExcelColumn("id", "ATT&CK ID"),
            ExcelColumn("name", "Nom", 32),
            ExcelColumn("aliases", "Aliases", 40),
            ExcelColumn("type", "Type"),
            ExcelColumn("description", "Description ATT&CK courte", 45),
            ExcelColumn("url", "ATT&CK URL", 50),
        ],
    )
