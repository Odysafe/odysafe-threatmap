"""Reusable executive-dashboard presentation helpers."""

from collections.abc import Mapping, Sequence
from typing import Any

from odysafe_threatmap.exporters.excel.security import escape_excel_value
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook, WorksheetWrapper


def write_dashboard_header(workbook: ExcelWorkbook, sheet: WorksheetWrapper, subtitle: str, context: str) -> None:
    target = sheet.worksheet
    target.hide_gridlines(2)
    target.set_tab_color(workbook.theme.colors["navy"])
    target.set_column(0, 13, 13)
    target.set_landscape()
    target.set_paper(9)
    target.fit_to_pages(1, 1)
    target.set_margins(0.25, 0.25, 0.35, 0.35)
    target.print_area(0, 0, 60, 13)
    target.merge_range(0, 0, 1, 13, "ODYSAFE THREATMAP — Dashboard CTI", workbook.theme.title_format)
    target.merge_range(2, 0, 2, 13, subtitle, workbook.theme.subtitle_format)
    target.merge_range(
        3,
        0,
        4,
        13,
        f"{context}\nLocal, deterministic, and reproducible analysis — no semantic inference",
        workbook.theme.context_format,
    )
    target.set_row(0, 27)
    target.set_row(1, 15)
    target.set_row(2, 22)
    target.set_row(3, 20)
    target.set_row(4, 20)


def write_kpi_cards(workbook: ExcelWorkbook, sheet: WorksheetWrapper, kpis: Mapping[str, Any], row: int = 6) -> None:
    palette = ["blue", "accent", "green", "orange", "grey", "navy", "red"]
    for index, (label, value) in enumerate(list(kpis.items())[:7]):
        start = index * 2
        color = workbook.theme.colors[palette[index]]
        label_fmt = workbook.xlsxwriter_workbook.add_format(
            {
                "bold": True,
                "font_size": 9,
                "font_color": "#FFFFFF",
                "bg_color": color,
                "border": 1,
                "border_color": color,
                "align": "center",
                "valign": "vcenter",
                "text_wrap": True,
            }
        )
        value_fmt = workbook.xlsxwriter_workbook.add_format(
            {
                "bold": True,
                "font_size": 15 if isinstance(value, str) and "\n" in value else 21,
                "font_color": color,
                "bg_color": "#FFFFFF",
                "border": 1,
                "border_color": color,
                "align": "center",
                "valign": "vcenter",
                "text_wrap": True,
            }
        )
        sheet.worksheet.merge_range(row, start, row, start + 1, label, label_fmt)
        sheet.worksheet.merge_range(row + 1, start, row + 2, start + 1, value, value_fmt)
    sheet.worksheet.set_row(row, 30)
    sheet.worksheet.set_row(row + 1, 23)
    sheet.worksheet.set_row(row + 2, 23)


def write_section_title(
    workbook: ExcelWorkbook, sheet: WorksheetWrapper, row: int, start_col: int, end_col: int, title: str
) -> None:
    sheet.worksheet.merge_range(row, start_col, row, end_col, title, workbook.theme.section_format)
    sheet.worksheet.set_row(row, 24)


def _banner(workbook: ExcelWorkbook, sheet: WorksheetWrapper, row: int, message: str, fmt: Any) -> None:
    sheet.worksheet.merge_range(row, 0, row + 1, 13, message, fmt)


def write_info_banner(workbook: ExcelWorkbook, sheet: WorksheetWrapper, row: int, message: str) -> None:
    _banner(workbook, sheet, row, f"ℹ  {message}", workbook.theme.info_format)


def write_warning_banner(workbook: ExcelWorkbook, sheet: WorksheetWrapper, row: int, message: str) -> None:
    _banner(workbook, sheet, row, f"⚠  {message}", workbook.theme.warning_format)


def write_empty_state(workbook: ExcelWorkbook, sheet: WorksheetWrapper, row: int, message: str) -> None:
    _banner(workbook, sheet, row, f"No usable data — {message}", workbook.theme.empty_format)


def write_small_analytic_table(
    workbook: ExcelWorkbook,
    sheet: WorksheetWrapper,
    row: int,
    col: int,
    title: str,
    data: Sequence[Mapping[str, Any]],
    width: int = 6,
) -> None:
    write_section_title(workbook, sheet, row, col, col + width - 1, title)
    if not data:
        sheet.worksheet.merge_range(
            row + 1, col, row + 3, col + width - 1, "No data available", workbook.theme.empty_format
        )
        return
    keys = list(data[0])
    for offset, key in enumerate(keys):
        sheet.worksheet.write(row + 1, col + offset, key, workbook.theme.table_header_format)
    for r, item in enumerate(data[:8], row + 2):
        for c, key in enumerate(keys):
            sheet.worksheet.write(r, col + c, escape_excel_value(item[key]), workbook.theme.wrap_format)
    for c in range(len(keys)):
        sheet.worksheet.set_column(col + c, col + c, max(10, width * 13 / len(keys)))


def _chart(
    workbook: ExcelWorkbook,
    sheet: WorksheetWrapper,
    data: Sequence[Mapping[str, Any]],
    title: str,
    row: int,
    col: int,
    chart_type: str,
) -> Any | None:
    if not data:
        return None
    keys = list(data[0])
    source_row = 100 + row + (col * 20)
    source_col = 0
    if len(keys) < 2:
        return None
    for offset, item in enumerate(data):
        sheet.worksheet.write(source_row + offset, source_col, escape_excel_value(item[keys[0]]))
        sheet.worksheet.write(source_row + offset, source_col + 1, item[keys[1]])
    chart = workbook.xlsxwriter_workbook.add_chart({"type": chart_type})
    series: dict[str, Any] = {
        "categories": [sheet.name, source_row, source_col, source_row + len(data) - 1, source_col],
        "values": [sheet.name, source_row, source_col + 1, source_row + len(data) - 1, source_col + 1],
        "fill": {"color": workbook.theme.colors["accent"]},
        "border": {"none": True},
    }
    if chart_type == "pie":
        series["data_labels"] = {"percentage": True, "leader_lines": True}
    chart.add_series(series)
    chart.set_title({"name": title, "name_font": {"color": "#163A5F", "bold": True, "size": 12}})
    chart.set_legend({"none": chart_type != "pie", "position": "bottom"})
    chart.set_chartarea({"border": {"color": "#D7E0E7"}, "fill": {"color": "#FFFFFF"}})
    chart.set_plotarea({"border": {"none": True}, "fill": {"color": "#FFFFFF"}})
    chart.set_size({"width": 520, "height": 285})
    sheet.worksheet.insert_chart(row, col, chart, {"x_offset": 5, "y_offset": 5})
    return chart


def add_dashboard_bar_chart(
    workbook: ExcelWorkbook,
    sheet: WorksheetWrapper,
    data: Sequence[Mapping[str, Any]],
    title: str,
    row: int,
    col: int,
    *,
    horizontal: bool = True,
) -> Any | None:
    return _chart(workbook, sheet, data, title, row, col, "bar" if horizontal else "column")


def add_dashboard_horizontal_bar_chart(
    workbook: ExcelWorkbook, sheet: WorksheetWrapper, data: Sequence[Mapping[str, Any]], title: str, row: int, col: int
) -> Any | None:
    return _chart(workbook, sheet, data, title, row, col, "bar")


def add_dashboard_pie_chart(
    workbook: ExcelWorkbook, sheet: WorksheetWrapper, data: Sequence[Mapping[str, Any]], title: str, row: int, col: int
) -> Any | None:
    return _chart(workbook, sheet, data, title, row, col, "pie")
