"""Reusable Excel table creation helpers."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from odysafe_threatmap.exporters.excel.security import escape_excel_value
from odysafe_threatmap.exporters.excel.theme import ExcelTheme
from odysafe_threatmap.utils.filenames import sanitize_filename


@dataclass(frozen=True, slots=True)
class ExcelColumn:
    """Definition of one exported table column."""

    key: str
    header: str
    width: int = 24


def _normalize_columns(columns: Sequence[str | ExcelColumn]) -> list[ExcelColumn]:
    return [column if isinstance(column, ExcelColumn) else ExcelColumn(column, column) for column in columns]


def create_excel_table(
    workbook: Any,
    worksheet: Any,
    data: Sequence[Mapping[str, Any]],
    start_row: int,
    start_col: int,
    columns: Sequence[str | ExcelColumn],
    theme: ExcelTheme | None = None,
) -> tuple[int, int, int, int]:
    """Write a safe Excel table and return its inclusive cell range."""
    target = getattr(worksheet, "worksheet", worksheet)
    target.hide_gridlines(2)
    target.set_tab_color("#245B8A")
    definitions = _normalize_columns(columns)
    if not definitions:
        raise ValueError("An Excel table requires at least one column.")
    active_theme = theme or getattr(workbook, "theme", None)
    if active_theme is None:
        raise ValueError("An Excel theme is required to create a table.")
    for row_offset, item in enumerate(data, start=1):
        for col_offset, column in enumerate(definitions):
            value = escape_excel_value(item.get(column.key))
            row = start_row + row_offset
            col = start_col + col_offset
            if isinstance(value, str) and value == "N/A":
                target.write(row, col, value, active_theme.na_format)
            elif isinstance(value, float) and any(
                token in column.key for token in ("percent", "percentage", "overlap")
            ):
                target.write_number(row, col, value, active_theme.percentage_format)
            elif isinstance(value, int) and column.key not in {"id", "attack_id"}:
                target.write_number(row, col, value, active_theme.count_format)
            elif (
                column.key in {"url", "attack_url"}
                and isinstance(value, str)
                and value.startswith(("https://", "http://"))
            ):
                target.write_url(row, col, value, active_theme.url_format, string=value)
            else:
                target.write(row, col, value, active_theme.wrap_format)
    end_row = start_row + max(1, len(data))
    end_col = start_col + len(definitions) - 1
    target.add_table(
        start_row,
        start_col,
        end_row,
        end_col,
        {
            "name": f"Table_{sanitize_filename(target.name).replace('-', '_')}_{start_row}_{start_col}",
            "style": "Table Style Medium 2",
            "columns": [
                {"header": column.header, "header_format": active_theme.table_header_format} for column in definitions
            ],
        },
    )
    active_theme.apply_table(target, start_row + 1, end_row, (start_col, end_col))
    for col_offset, column in enumerate(definitions):
        target.set_column(start_col + col_offset, start_col + col_offset, min(max(column.width, 8), 50))
    target.freeze_panes(start_row + 1, start_col)
    if data:
        numeric_tokens = (
            "count",
            "occurrences",
            "groups",
            "software",
            "mitigations",
            "components",
            "score",
            "reports",
            "sources",
            "words",
            "iocs",
            "ttps",
        )
        for offset, column in enumerate(definitions):
            if any(token in column.key for token in numeric_tokens):
                target.conditional_format(
                    start_row + 1,
                    start_col + offset,
                    end_row,
                    start_col + offset,
                    {"type": "data_bar", "bar_color": "#3E78B2", "bar_solid": True},
                )
    return start_row, start_col, end_row, end_col
