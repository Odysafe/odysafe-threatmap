"""Enriched ATT&CK technique worksheet."""

from odysafe_threatmap.domain.models import AttackTechnique, ExtractionResult
from odysafe_threatmap.exporters.excel.display_text import format_list, format_yes_no, truncate_display_text
from odysafe_threatmap.exporters.excel.sheets.common import write_no_data_banner
from odysafe_threatmap.exporters.excel.tables import ExcelColumn, create_excel_table
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook


def write_ttps_sheet(
    workbook: ExcelWorkbook,
    ttps: list[AttackTechnique],
    extraction_result: ExtractionResult,
    statuses: dict[str, str] | None = None,
) -> None:
    """Write every explicit technique ID and preserve its local resolution status."""
    sheet = workbook.add_sheet("TTPs")
    occurrences = {item.attack_id: item.occurrences for item in extraction_result.ttps}
    statuses = statuses or {}
    resolved = {item.attack_id: item for item in ttps}
    rows = [
        {
            "id": extracted.attack_id,
            "status": statuses.get(extracted.attack_id, "ACTIVE" if extracted.validated else "UNKNOWN"),
            "name": item.name if item else "N/A",
            "tactics": format_list(item.tactics) if item else "N/A",
            "platforms": format_list(item.platforms) if item else "N/A",
            "description": truncate_display_text(item.description, 320) if item else "N/A",
            "subtechnique": format_yes_no(item.is_subtechnique) if item else "N/A",
            "occurrences": occurrences.get(extracted.attack_id, 0),
            "groups": item.groups_count if item else "N/A",
            "software": item.software_count if item else "N/A",
            "mitigations": len(item.mitigations) if item else "N/A",
            "components": len(item.data_components) if item else "N/A",
        }
        for extracted in extraction_result.ttps
        for item in [resolved.get(extracted.attack_id)]
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
            ExcelColumn("id", "Technique ID"),
            ExcelColumn("status", "Local status"),
            ExcelColumn("name", "Technique", 32),
            ExcelColumn("tactics", "Tactic(s)", 28),
            ExcelColumn("platforms", "Platform(s)", 28),
            ExcelColumn("description", "Short ATT&CK description", 45),
            ExcelColumn("subtechnique", "Sub-technique"),
            ExcelColumn("occurrences", "Occurrences"),
            ExcelColumn("groups", "ATT&CK groups"),
            ExcelColumn("software", "ATT&CK software"),
            ExcelColumn("mitigations", "Mitigations"),
            ExcelColumn("components", "Detection components"),
        ],
    )
