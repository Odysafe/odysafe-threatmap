"""Hidden reproducibility metadata worksheet."""

from typing import Any

from odysafe_threatmap.config.loader import compute_embedded_config_hash
from odysafe_threatmap.exporters.excel.tables import ExcelColumn, create_excel_table
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook, WorksheetWrapper

META_FIELDS = (
    "odysafe_threatmap_version",
    "generated_at_utc",
    "attack_version",
    "attack_stix_version",
    "attack_bundle_path",
    "attack_bundle_sha256",
    "attack_source_type",
    "attack_source_ref",
    "mitreattack_python_version",
    "iocsearcher_version",
    "txt2stix_version",
    "input_hashes",
    "config_hash_or_version",
    "offline_mode",
    "command",
)


def write_meta_sheet(workbook: ExcelWorkbook, metadata: dict[str, Any]) -> WorksheetWrapper:
    """Create the hidden _Meta sheet with reproducibility fields."""
    sheet = workbook.add_sheet("_Meta", hidden=True)
    resolved = dict(metadata)
    if not resolved.get("config_hash_or_version") or resolved.get("config_hash_or_version") == "N/A":
        resolved["config_hash_or_version"] = compute_embedded_config_hash()
    rows = [{"field": field, "value": resolved.get(field, "N/A")} for field in META_FIELDS]
    rows.extend(
        {"field": field, "value": value} for field, value in sorted(resolved.items()) if field not in META_FIELDS
    )
    create_excel_table(
        workbook,
        sheet,
        rows,
        start_row=0,
        start_col=0,
        columns=[ExcelColumn("field", "Field", 32), ExcelColumn("value", "Value", 50)],
        theme=workbook.theme,
    )
    return sheet
