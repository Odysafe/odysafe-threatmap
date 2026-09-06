"""Centralized Odysafe visual language for every generated workbook."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ExcelTheme:
    workbook: Any
    colors: dict[str, str] = field(init=False)

    def __post_init__(self) -> None:
        self.colors = {
            "navy": "#163A5F",
            "blue": "#245B8A",
            "accent": "#3E78B2",
            "light_blue": "#DCE9F5",
            "green": "#2E7D32",
            "light_green": "#E8F5E9",
            "orange": "#ED8B00",
            "light_orange": "#FFF3E0",
            "red": "#C62828",
            "light_red": "#FFEBEE",
            "grey": "#607D8B",
            "light_grey": "#ECEFF1",
            "text": "#263238",
            "background": "#F5F7FA",
            "white": "#FFFFFF",
            "success": "#2E7D32",
            "warning": "#ED8B00",
            "critical": "#C62828",
            "info": "#245B8A",
            "neutral": "#607D8B",
            "header": "#163A5F",
            "table_alt": "#DCE9F5",
        }
        add = self.workbook.add_format
        self.header_format = add(
            {"bold": True, "bg_color": "#163A5F", "font_color": "#FFFFFF", "border": 1, "valign": "vcenter"}
        )
        self.title_format = add(
            {
                "bold": True,
                "font_size": 22,
                "font_color": "#FFFFFF",
                "bg_color": "#163A5F",
                "font_name": "Aptos Display",
                "align": "left",
                "valign": "vcenter",
            }
        )
        self.sheet_title_format = add(
            {"bold": True, "font_size": 20, "font_color": "#163A5F", "font_name": "Aptos Display"}
        )
        self.subtitle_format = add({"font_size": 11, "font_color": "#607D8B", "font_name": "Aptos"})
        self.context_format = add(
            {
                "font_size": 10,
                "font_color": "#163A5F",
                "bg_color": "#DCE9F5",
                "border": 1,
                "border_color": "#B7CADB",
                "valign": "vcenter",
                "text_wrap": True,
            }
        )
        self.section_format = add(
            {"bold": True, "font_size": 12, "font_color": "#FFFFFF", "bg_color": "#245B8A", "valign": "vcenter"}
        )
        self.info_format = add(
            {
                "font_color": "#163A5F",
                "bg_color": "#DCE9F5",
                "border": 1,
                "border_color": "#B7CADB",
                "text_wrap": True,
                "valign": "vcenter",
            }
        )
        self.warning_format = add(
            {
                "bold": True,
                "font_color": "#7A4700",
                "bg_color": "#FFF3E0",
                "border": 1,
                "border_color": "#ED8B00",
                "text_wrap": True,
                "valign": "vcenter",
            }
        )
        self.empty_format = add(
            {
                "italic": True,
                "font_color": "#607D8B",
                "bg_color": "#ECEFF1",
                "border": 1,
                "align": "center",
                "valign": "vcenter",
            }
        )
        self.kpi_format = add(
            {
                "bold": True,
                "font_size": 22,
                "font_color": "#245B8A",
                "bg_color": "#FFFFFF",
                "border": 1,
                "align": "center",
                "valign": "vcenter",
            }
        )
        self.kpi_label_format = add(
            {
                "bold": True,
                "font_color": "#FFFFFF",
                "bg_color": "#245B8A",
                "border": 1,
                "align": "center",
                "valign": "vcenter",
                "text_wrap": True,
            }
        )
        self.table_header_format = self.header_format
        self.table_row_format = add({"bg_color": "#FFFFFF", "border": 1, "border_color": "#D7E0E7", "valign": "top"})
        self.border_format = add({"border": 1, "border_color": "#D7E0E7"})
        self.wrap_format = add({"text_wrap": True, "valign": "top", "border": 1, "border_color": "#D7E0E7"})
        self.date_format = add({"num_format": "yyyy-mm-dd hh:mm", "border": 1})
        self.url_format = add({"font_color": "#0563C1", "underline": 1, "border": 1})
        self.na_format = add({"bg_color": "#ECEFF1", "font_color": "#607D8B", "italic": True, "border": 1})
        self.percentage_format = add({"num_format": "0.0%", "text_wrap": True, "valign": "top", "border": 1})
        self.count_format = add({"num_format": "#,##0", "text_wrap": True, "valign": "top", "border": 1})

    def apply_header(self, worksheet: Any, row: int, col_range: tuple[int, int]) -> None:
        getattr(worksheet, "worksheet", worksheet).set_row(row, 28, self.table_header_format)

    def apply_table(self, worksheet: Any, start_row: int, end_row: int, col_range: tuple[int, int]) -> None:
        target = getattr(worksheet, "worksheet", worksheet)
        for row in range(start_row, end_row + 1):
            target.set_row(row, 30)

    def apply_kpi(self, worksheet: Any, row: int, col: int, value: Any, label: str) -> None:
        target = getattr(worksheet, "worksheet", worksheet)
        target.write(row, col, label, self.kpi_label_format)
        target.write(row + 1, col, value, self.kpi_format)
