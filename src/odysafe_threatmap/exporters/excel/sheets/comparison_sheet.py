"""Multi-actor technique comparison worksheet."""

from odysafe_threatmap.application.actor_snapshot import ActorSnapshotResult
from odysafe_threatmap.exporters.excel.tables import ExcelColumn, create_excel_table
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook


def write_comparison_sheet(workbook: ExcelWorkbook, snapshot_result: ActorSnapshotResult) -> None:
    """Write the actor comparison matrix for snapshots with multiple actors."""
    if len(snapshot_result.actors) < 2:
        return
    sheet = workbook.add_sheet("Comparaison acteurs")
    actor_count = len(snapshot_result.actors)
    last_column = actor_count + 3
    sheet.worksheet.merge_range(0, 0, 0, last_column, "Actor Technique Comparison", workbook.theme.title_format)
    sheet.worksheet.merge_range(
        1,
        0,
        2,
        last_column,
        "A check mark means a direct ATT&CK group-to-technique relationship. Blank cells mean no direct relationship.",
        workbook.theme.context_format,
    )
    sheet.worksheet.merge_range(4, 0, 4, 1, "Actors compared", workbook.theme.kpi_label_format)
    sheet.worksheet.merge_range(5, 0, 6, 1, actor_count, workbook.theme.kpi_format)
    sheet.worksheet.merge_range(4, 2, 4, 3, "Distinct techniques", workbook.theme.kpi_label_format)
    sheet.worksheet.merge_range(5, 2, 6, 3, len(snapshot_result.techniques), workbook.theme.kpi_format)
    sheet.worksheet.set_row(0, 34)
    sheet.worksheet.set_row(1, 25)
    sheet.worksheet.set_row(2, 25)
    sheet.worksheet.set_row(4, 28)
    sheet.worksheet.set_row(5, 24)
    sheet.worksheet.set_row(6, 24)
    rows = []
    technique_ids_by_actor = {
        actor.stix_id: {item.stix_id for item in snapshot_result.actor_techniques[actor.stix_id]}
        for actor in snapshot_result.actors
    }
    for technique in snapshot_result.techniques:
        row: dict[str, str | int | float] = {"attack_id": technique.attack_id, "name": technique.name}
        present = 0
        for actor in snapshot_result.actors:
            matched = technique.stix_id in technique_ids_by_actor[actor.stix_id]
            row[actor.stix_id] = "✓" if matched else ""
            present += int(matched)
        row["actor_count"] = present
        row["coverage_percent"] = present / actor_count
        rows.append(row)
    rows.sort(key=lambda row: (-int(row["actor_count"]), str(row["attack_id"])))
    columns = [ExcelColumn("attack_id", "Technique ID", 14), ExcelColumn("name", "Technique name", 32)]
    columns.extend(
        ExcelColumn(actor.stix_id, f"{actor.name} ({actor.attack_id})", 13) for actor in snapshot_result.actors
    )
    columns.extend(
        (
            ExcelColumn("actor_count", "Actor count", 13),
            ExcelColumn("coverage_percent", "Actor coverage", 15),
        )
    )
    table_start_row = 8
    create_excel_table(workbook, sheet, rows, table_start_row, 0, columns)
    sheet.worksheet.set_zoom(85 if actor_count <= 8 else 70)
    sheet.worksheet.freeze_panes(table_start_row + 1, 0)
    sheet.worksheet.set_landscape()
    sheet.worksheet.fit_to_pages(1, 0)
    sheet.worksheet.repeat_rows(table_start_row, table_start_row)
    sheet.worksheet.set_row(table_start_row, 58)
    matrix_format = workbook.xlsxwriter_workbook.add_format(
        {"align": "center", "valign": "vcenter", "border": 1, "border_color": "#D7E0E7"}
    )
    sheet.worksheet.set_column(2, actor_count + 1, 15, matrix_format)
    sheet.worksheet.set_column(actor_count + 2, actor_count + 2, 13, workbook.theme.count_format)
    sheet.worksheet.set_column(actor_count + 3, actor_count + 3, 15, workbook.theme.percentage_format)
    if rows:
        first_actor_col = 2
        last_actor_col = first_actor_col + len(snapshot_result.actors) - 1
        sheet.worksheet.conditional_format(
            table_start_row + 1,
            first_actor_col,
            table_start_row + len(rows),
            last_actor_col,
            {
                "type": "text",
                "criteria": "containing",
                "value": "✓",
                "format": workbook.xlsxwriter_workbook.add_format(
                    {"bg_color": "#E8F5E9", "font_color": "#2E7D32", "bold": True, "align": "center"}
                ),
            },
        )
        sheet.worksheet.conditional_format(
            table_start_row + 1,
            last_actor_col + 1,
            table_start_row + len(rows),
            last_actor_col + 1,
            {
                "type": "data_bar",
                "bar_color": workbook.theme.colors["accent"],
            },
        )
        coverage_col = last_actor_col + 2
        sheet.worksheet.conditional_format(
            table_start_row + 1,
            coverage_col,
            table_start_row + len(rows),
            coverage_col,
            {"type": "3_color_scale", "min_color": "#FCE8E6", "mid_color": "#FFF4CC", "max_color": "#D9EAD3"},
        )

    chart_start_row = table_start_row + len(rows) + 4
    sheet.worksheet.merge_range(
        chart_start_row,
        0,
        chart_start_row,
        last_column,
        "ATT&CK Technique Coverage by Actor",
        workbook.theme.section_format,
    )
    sheet.worksheet.merge_range(
        chart_start_row + 1,
        0,
        chart_start_row + 2,
        last_column,
        "Counts represent direct ATT&CK group-to-technique relationships in the installed snapshot.",
        workbook.theme.info_format,
    )
    data_start_row = chart_start_row + 4
    sheet.worksheet.write(data_start_row, 0, "Actor", workbook.theme.table_header_format)
    sheet.worksheet.write(data_start_row, 1, "Direct techniques", workbook.theme.table_header_format)
    for row_number, actor in enumerate(snapshot_result.actors, start=data_start_row + 1):
        sheet.worksheet.write(row_number, 0, f"{actor.name} ({actor.attack_id})", workbook.theme.wrap_format)
        sheet.worksheet.write_number(
            row_number,
            1,
            len(snapshot_result.actor_techniques[actor.stix_id]),
            workbook.theme.count_format,
        )
    chart = workbook.xlsxwriter_workbook.add_chart({"type": "bar"})
    chart.add_series(
        {
            "name": "Direct techniques",
            "categories": [sheet.name, data_start_row + 1, 0, data_start_row + actor_count, 0],
            "values": [sheet.name, data_start_row + 1, 1, data_start_row + actor_count, 1],
            "fill": {"color": workbook.theme.colors["accent"]},
            "data_labels": {"value": True},
        }
    )
    chart.set_title({"name": "Direct ATT&CK techniques per selected actor"})
    chart.set_x_axis({"name": "Number of direct techniques", "major_gridlines": {"visible": True}})
    chart.set_y_axis({"name": "Selected ATT&CK groups"})
    chart.set_legend({"none": True})
    chart.set_style(10)
    chart.set_size({"width": 900, "height": max(420, min(1000, actor_count * 32 + 180))})
    sheet.worksheet.insert_chart(data_start_row, 3, chart)
