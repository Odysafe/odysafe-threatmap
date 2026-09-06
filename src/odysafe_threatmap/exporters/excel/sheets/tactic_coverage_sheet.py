"""ATT&CK tactic coverage worksheet."""

from collections import Counter

from odysafe_threatmap.domain.models import AttackTechnique
from odysafe_threatmap.exporters.excel.sheets.common import write_no_data_banner
from odysafe_threatmap.exporters.excel.tables import ExcelColumn, create_excel_table
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook


def write_tactic_coverage_sheet(workbook: ExcelWorkbook, ttps: list[AttackTechnique]) -> None:
    """Write deterministic technique coverage counts by tactic."""
    sheet = workbook.add_sheet("Couverture Tactiques")
    counts = Counter(tactic for item in ttps for tactic in item.tactics)
    rows = (
        [
            {
                "tactic": tactic,
                "techniques": count,
                "percentage": count / len(ttps),
                "technique_ids": " • ".join(item.attack_id for item in ttps if tactic in item.tactics),
            }
            for tactic, count in sorted(counts.items())
        ]
        if ttps
        else []
    )
    if not rows:
        write_no_data_banner(sheet, 0)
    create_excel_table(
        workbook,
        sheet,
        rows,
        2 if not rows else 0,
        0,
        [
            ExcelColumn("tactic", "Tactique", 32),
            ExcelColumn("techniques", "Nb techniques"),
            ExcelColumn("percentage", "Part des TTPs du rapport"),
            ExcelColumn("technique_ids", "IDs", 40),
        ],
    )
