"""Report metadata worksheet."""

from typing import Any

from odysafe_threatmap.domain.models import ExtractionResult, ReportMetadata
from odysafe_threatmap.domain.scoring import interpret_cti_density
from odysafe_threatmap.exporters.excel.tables import ExcelColumn, create_excel_table
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook


def write_report_sheet(
    workbook: ExcelWorkbook,
    metadata: ReportMetadata,
    extraction_result: ExtractionResult,
    actor_count: int,
    cti_density: float | None,
) -> None:
    """Write source metadata and deterministic extraction totals."""
    sheet = workbook.add_sheet("Rapport")
    density = interpret_cti_density(cti_density)
    rows: list[dict[str, Any]] = [
        {"field": "Nom", "value": metadata.name},
        {"field": "Source", "value": metadata.source or "N/A"},
        {
            "field": "Date de publication",
            "value": metadata.published_date.isoformat() if metadata.published_date else "N/A",
        },
        {"field": "TLP", "value": metadata.tlp or "N/A"},
        {"field": "Confidence", "value": metadata.confidence or "N/A"},
        {"field": "Fichier", "value": metadata.filename},
        {"field": "SHA-256", "value": metadata.sha256},
        {"field": "Nombre de mots", "value": metadata.word_count},
        {"field": "Nombre de lignes", "value": metadata.line_count},
        {"field": "IOCs uniques", "value": len(extraction_result.indicators)},
        {"field": "Occurrences IOC", "value": sum(item.occurrences for item in extraction_result.indicators)},
        {"field": "TTPs uniques", "value": len(extraction_result.ttps)},
        {"field": "Occurrences TTP", "value": sum(item.occurrences for item in extraction_result.ttps)},
        {"field": "TTPs ATT&CK validées", "value": sum(item.validated for item in extraction_result.ttps)},
        {"field": "Acteurs/campagnes explicitement mentionnés", "value": actor_count},
        {
            "field": "CTI Observation Density",
            "value": f"{cti_density:.1f} observations / 1,000 words" if cti_density is not None else "N/A",
        },
        {"field": "CTI Density Interpretation", "value": density.label},
        {"field": "What this value means", "value": density.explanation},
        {
            "field": "CTI Density Formula",
            "value": "(IOC occurrences + explicit TTP occurrences) / report word count × 1,000",
        },
        {"field": "Counting basis", "value": "Occurrences, not unique values"},
    ]
    create_excel_table(
        workbook, sheet, rows, 0, 0, [ExcelColumn("field", "Champ", 40), ExcelColumn("value", "Valeur", 50)]
    )
