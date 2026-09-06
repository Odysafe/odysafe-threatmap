"""Executive summary worksheet for Module B."""

from collections import Counter

from odysafe_threatmap.application.actor_snapshot import ActorSnapshotResult
from odysafe_threatmap.exporters.excel.dashboard import (
    add_dashboard_bar_chart,
    write_dashboard_header,
    write_kpi_cards,
    write_small_analytic_table,
)
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook, WorksheetWrapper


def write_summary_sheet_b(workbook: ExcelWorkbook, result: ActorSnapshotResult) -> WorksheetWrapper:
    sheet = workbook.add_sheet("Synthèse")
    write_dashboard_header(
        workbook,
        sheet,
        "Threat Actor Snapshot",
        f"{', '.join(actor.name for actor in result.actors)} • ATT&CK {result.attack_version or 'N/A'} • Offline mode",
    )
    sheet.worksheet.write(2, 0, "Actors", workbook.theme.subtitle_format)
    write_kpi_cards(
        workbook,
        sheet,
        {
            "Actors analysed": len(result.actors),
            "Unique TTPs": len(result.techniques),
            "Software": len(result.software),
            "Campaigns": len(result.campaigns),
        },
    )
    selected_actor_coverage = Counter(item.stix_id for values in result.actor_techniques.values() for item in values)
    popularity = sorted(
        (
            {
                "Technique": f"{item.attack_id} — {item.name}",
                "Selected actors": selected_actor_coverage[item.stix_id],
            }
            for item in result.techniques
        ),
        key=lambda row: (
            -(row["Selected actors"] if isinstance(row["Selected actors"], int) else 0),
            str(row["Technique"]),
        ),
    )[:10]
    tactics = Counter(tactic for item in result.techniques for tactic in item.tactics)
    software = Counter(record.name for values in result.actor_software.values() for record in values)
    add_dashboard_bar_chart(workbook, sheet, popularity, "Techniques shared by selected actors", 11, 0)
    add_dashboard_bar_chart(
        workbook,
        sheet,
        [{"Tactic": key, "Techniques": value} for key, value in tactics.most_common()],
        "Technique distribution by tactic",
        11,
        7,
        horizontal=False,
    )
    add_dashboard_bar_chart(
        workbook,
        sheet,
        [{"Software": key, "Actors": value} for key, value in software.most_common(8)],
        "Most shared software",
        29,
        0,
    )
    if len(result.actors) > 1:
        add_dashboard_bar_chart(
            workbook,
            sheet,
            [
                {
                    "Actor": f"{actor.name} ({actor.attack_id})",
                    "Direct techniques": len(result.actor_techniques.get(actor.stix_id, ())),
                }
                for actor in sorted(result.actors, key=lambda item: item.name.casefold())
            ],
            "Direct techniques by actor",
            29,
            7,
        )
    write_small_analytic_table(workbook, sheet, 47, 0, "Leading techniques", popularity[:6], 6)
    return sheet
