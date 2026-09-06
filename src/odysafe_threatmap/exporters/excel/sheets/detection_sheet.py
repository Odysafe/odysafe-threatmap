"""ATT&CK data component detection worksheet."""

from odysafe_threatmap.domain.models import AttackTechnique
from odysafe_threatmap.exporters.excel.sheets.common import write_no_data_banner
from odysafe_threatmap.exporters.excel.tables import ExcelColumn, create_excel_table
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook


def write_detection_sheet(workbook: ExcelWorkbook, ttps: list[AttackTechnique]) -> None:
    """Write one detection row for each technique and data component pair."""
    sheet = workbook.add_sheet("Détection")
    rows = [
        {"id": item.attack_id, "name": item.name, "component": component.name, "source": component.data_source_name}
        for item in ttps
        for component in item.data_components
    ]
    workbook.write_title(sheet, 0, 0, "Détection ATT&CK")
    if not rows:
        write_no_data_banner(
            sheet, 2, "ℹ Aucun composant de détection ATT&CK documenté pour les techniques présentes dans ce rapport."
        )
    create_excel_table(
        workbook,
        sheet,
        rows,
        4 if not rows else 2,
        0,
        [
            ExcelColumn("id", "ID technique"),
            ExcelColumn("name", "Technique", 32),
            ExcelColumn("component", "Composant de données", 40),
            ExcelColumn("source", "Source de données", 40),
        ],
    )
