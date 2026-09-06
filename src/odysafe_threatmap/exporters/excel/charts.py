"""Simple, themed charts for summary sheets."""

from collections.abc import Mapping, Sequence
from typing import Any

from odysafe_threatmap.exporters.excel.security import escape_excel_value


def create_bar_chart(
    workbook: Any,
    worksheet: Any,
    data: Sequence[Mapping[str, Any]],
    start_row: int,
    start_col: int,
    title: str,
    x_label: str,
    y_label: str,
) -> Any | None:
    """Create and insert a bar chart from the first two keys of each mapping."""
    if not data:
        return None
    target = getattr(worksheet, "worksheet", worksheet)
    keys = list(data[0])
    if len(keys) < 2:
        raise ValueError("Bar chart data requires category and value keys.")
    category_key, value_key = keys[:2]
    target.write(start_row, start_col, category_key)
    target.write(start_row, start_col + 1, value_key)
    for index, item in enumerate(data, start=1):
        target.write(start_row + index, start_col, escape_excel_value(item[category_key]))
        target.write(start_row + index, start_col + 1, item[value_key])
    chart = workbook.xlsxwriter_workbook.add_chart({"type": "bar"})
    chart.add_series(
        {
            "name": [target.name, start_row, start_col + 1],
            "categories": [target.name, start_row + 1, start_col, start_row + len(data), start_col],
            "values": [target.name, start_row + 1, start_col + 1, start_row + len(data), start_col + 1],
        }
    )
    chart.set_title({"name": title})
    chart.set_x_axis({"name": x_label})
    chart.set_y_axis({"name": y_label})
    chart.set_style(10)
    target.insert_chart(start_row, start_col + 3, chart)
    return chart
