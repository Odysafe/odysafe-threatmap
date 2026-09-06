"""Excel composition for local Sector Threat Profiles."""

from collections import Counter
from pathlib import Path

from odysafe_threatmap import __version__
from odysafe_threatmap.application.sector_profile import SectorProfileResult
from odysafe_threatmap.exporters.excel.dashboard import (
    add_dashboard_bar_chart,
    add_dashboard_pie_chart,
    write_dashboard_header,
    write_kpi_cards,
    write_small_analytic_table,
)
from odysafe_threatmap.exporters.excel.provenance import build_provenance
from odysafe_threatmap.exporters.excel.sheets.meta_sheet import write_meta_sheet
from odysafe_threatmap.exporters.excel.tables import ExcelColumn, create_excel_table
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook


def _table(workbook: ExcelWorkbook, name: str, rows: list[dict[str, object]], columns: list[ExcelColumn]) -> None:
    sheet = workbook.add_sheet(name)
    create_excel_table(workbook, sheet, rows, 0, 0, columns)


def build_sector_workbook(profile_result: SectorProfileResult, output_path: Path, command: str) -> Path:
    """Write the Module C workbook in its prescribed sheet order."""
    metadata = {
        "inputs": [item.name for item in profile_result.sectors],
        "hashes": {},
        "parameters": {"command": command},
        "versions": {"odysafe-threatmap": __version__},
        "attack_dataset": {
            "version": profile_result.attack_version,
            "path": profile_result.attack_bundle_path,
            "sha256": profile_result.attack_bundle_sha256,
        },
    }
    with ExcelWorkbook(output_path, metadata=metadata) as workbook:
        summary = workbook.add_sheet("Synthèse")
        write_dashboard_header(
            workbook,
            summary,
            "Profil de menace sectoriel",
            f"{', '.join(item.name for item in profile_result.sectors)} • ATT&CK {profile_result.attack_version or 'N/A'} • Priorisation locale Odysafe",
        )
        critical = sum(
            "Critical" in item.priority_label or "Critique" in item.priority_label
            for item in profile_result.risk_matrix
        )
        write_kpi_cards(
            workbook,
            summary,
            {
                "Secteurs analysés": len(profile_result.sectors),
                "Acteurs": len(profile_result.actors),
                "TTPs distinctes": len(profile_result.techniques),
                "Régions": len(profile_result.regions_data),
                "Priorités critiques": critical,
            },
        )
        tactics = Counter(
            item.technique.tactics[0] if item.technique.tactics else "N/A" for item in profile_result.techniques
        )
        priorities = Counter(item.priority_label for item in profile_result.risk_matrix)
        add_dashboard_bar_chart(
            workbook, summary, [{"Tactique": k, "TTPs": v} for k, v in tactics.most_common()], "Top tactiques", 11, 0
        )
        add_dashboard_bar_chart(
            workbook,
            summary,
            [
                {"TTP": f"{item.technique.attack_id} — {item.technique.name}", "Acteurs": item.sector_groups_count}
                for item in profile_result.techniques[:10]
            ],
            "Top TTPs",
            11,
            7,
        )
        add_dashboard_bar_chart(
            workbook,
            summary,
            [
                {"Acteur": actor.name, "TTPs": len(profile_result.actor_techniques[actor.stix_id])}
                for actor in profile_result.actors[:8]
            ],
            "Top acteurs",
            29,
            0,
        )
        add_dashboard_pie_chart(
            workbook,
            summary,
            [{"Priorité": k, "Nombre": v} for k, v in priorities.items()],
            "Distribution des priorités",
            29,
            7,
        )
        if profile_result.regions_data:
            add_dashboard_bar_chart(
                workbook,
                summary,
                [{"Région": k, "Acteurs": len(v)} for k, v in profile_result.regions_data.items()],
                "Répartition régionale",
                47,
                0,
            )
        write_small_analytic_table(
            workbook,
            summary,
            47,
            8,
            "Priorisation locale Odysafe",
            [
                {
                    "ID": item.technique_id,
                    "Technique": item.technique_name,
                    "Score": item.priority_score,
                    "Priorité": item.priority_label,
                }
                for item in profile_result.risk_matrix[:6]
            ],
            6,
        )
        _table(
            workbook,
            "Secteur",
            [
                {
                    "sector": item.name,
                    "groups": item.groups_count,
                    "techniques": item.techniques_count,
                    "source": item.mapping_source,
                    "version": item.mapping_version,
                }
                for item in profile_result.sectors
            ],
            [
                ExcelColumn("sector", "Sector"),
                ExcelColumn("groups", "Groups"),
                ExcelColumn("techniques", "Distinct techniques"),
                ExcelColumn("source", "Mapping source"),
                ExcelColumn("version", "Mapping version"),
            ],
        )
        _table(
            workbook,
            "Acteurs",
            [
                {
                    "id": actor.attack_id,
                    "name": actor.name,
                    "ttps": len(profile_result.actor_techniques[actor.stix_id]),
                    "sectors": ", ".join(actor.sectors) or "N/A",
                    "regions": ", ".join(actor.regions) or "N/A",
                }
                for actor in profile_result.actors
            ],
            [
                ExcelColumn("id", "ATT&CK ID"),
                ExcelColumn("name", "Name"),
                ExcelColumn("ttps", "TTPs"),
                ExcelColumn("sectors", "Sectors", 30),
                ExcelColumn("regions", "Regions", 30),
            ],
        )
        _table(
            workbook,
            "TTPs",
            [
                {
                    "id": item.technique.attack_id,
                    "name": item.technique.name,
                    "tactic": ", ".join(item.technique.tactics) or "N/A",
                    "groups": item.sector_groups_count,
                    "percent": item.sector_groups_percent,
                    "actors": ", ".join(item.sector_groups),
                }
                for item in profile_result.techniques
            ],
            [
                ExcelColumn("id", "Technique ID"),
                ExcelColumn("name", "Name"),
                ExcelColumn("tactic", "Tactic"),
                ExcelColumn("groups", "Sector groups"),
                ExcelColumn("percent", "Sector groups (%)"),
                ExcelColumn("actors", "Groups", 35),
            ],
        )
        risk_sheet = workbook.add_sheet("Matrice de risque")
        workbook.write_subtitle(risk_sheet, 0, 0, "Odysafe local prioritization — configurable heuristic")
        create_excel_table(
            workbook,
            risk_sheet,
            [
                {
                    "id": item.technique_id,
                    "name": item.technique_name,
                    "tactic": item.tactic,
                    "frequency": item.frequency_score,
                    "impact": item.tactic_impact_score,
                    "score": item.priority_score,
                    "priority": item.priority_label,
                }
                for item in profile_result.risk_matrix
            ],
            2,
            0,
            [
                ExcelColumn("id", "Technique ID"),
                ExcelColumn("name", "Name"),
                ExcelColumn("tactic", "Tactic"),
                ExcelColumn("frequency", "Frequency (%)"),
                ExcelColumn("impact", "Impact score"),
                ExcelColumn("score", "Priority score"),
                ExcelColumn("priority", "Priority"),
            ],
        )
        _table(
            workbook,
            "Régions",
            [
                {
                    "region": region,
                    "groups": len(actors),
                    "actors": ", ".join(actor.name for actor in actors),
                    "sectors": ", ".join(sorted({sector for actor in actors for sector in actor.sectors})),
                }
                for region, actors in profile_result.regions_data.items()
            ],
            [
                ExcelColumn("region", "Region"),
                ExcelColumn("groups", "Group count"),
                ExcelColumn("actors", "Groups", 35),
                ExcelColumn("sectors", "Associated sectors", 35),
            ],
        )
        write_meta_sheet(
            workbook,
            build_provenance(
                attack_version=profile_result.attack_version,
                stix_version=profile_result.attack_stix_version,
                attack_bundle_path=profile_result.attack_bundle_path,
                attack_bundle_sha256=profile_result.attack_bundle_sha256,
                command=command,
                input_note="Not applicable — input is explicit local sector configuration",
            ),
        )
    return output_path
