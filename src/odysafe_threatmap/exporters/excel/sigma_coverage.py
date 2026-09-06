"""Excel composition for strict Sigma coverage."""

from collections import Counter
from pathlib import Path

from odysafe_threatmap import __version__
from odysafe_threatmap.application.sigma_coverage import SigmaCoverageResult
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


def build_coverage_workbook(coverage_result: SigmaCoverageResult, output_path: Path, command: str) -> Path:
    """Write the Module H workbook in its required sheet order."""
    metadata = {
        "inputs": [],
        "hashes": {},
        "parameters": {"command": command},
        "versions": {"odysafe-threatmap": __version__},
        "attack_dataset": {
            "version": coverage_result.attack_version,
            "path": coverage_result.attack_bundle_path,
            "sha256": coverage_result.attack_bundle_sha256,
        },
    }
    with ExcelWorkbook(output_path, metadata=metadata) as workbook:
        total = len(coverage_result.coverage)
        summary = workbook.add_sheet("Synthèse")
        exact_percent = coverage_result.exact_count / total if total else 0
        combined_percent = (coverage_result.exact_count + coverage_result.partial_count) / total if total else 0
        critical_uncovered = sum(
            item.status == "none" and ("Critical" in item.priority or "Critique" in item.priority)
            for item in coverage_result.coverage
        )
        write_dashboard_header(
            workbook,
            summary,
            "Couverture de détection Sigma",
            f"Correspondance stricte par tags ATT&CK • ATT&CK {coverage_result.attack_version or 'N/A'} • Mode offline",
        )
        write_kpi_cards(
            workbook,
            summary,
            {
                "Techniques": total,
                "Couvertes": coverage_result.exact_count,
                "Partielles": coverage_result.partial_count,
                "Non couvertes": coverage_result.none_count,
                "% exact": f"{exact_percent:.0%}",
                "% exact + partiel": f"{combined_percent:.0%}",
                "Critiques non couvertes": critical_uncovered,
            },
        )
        status = Counter(item.status for item in coverage_result.coverage)
        priority = Counter(item.priority for item in coverage_result.coverage)
        uncovered_tactics = Counter(
            tactic for item in coverage_result.coverage if item.status == "none" for tactic in item.technique.tactics
        )
        add_dashboard_pie_chart(
            workbook,
            summary,
            [{"Statut": k, "Techniques": v} for k, v in status.items()],
            "Répartition de la couverture",
            11,
            0,
        )
        add_dashboard_bar_chart(
            workbook,
            summary,
            [{"Priorité": k, "Techniques": v} for k, v in priority.items()],
            "Priorités",
            11,
            7,
            horizontal=False,
        )
        add_dashboard_bar_chart(
            workbook,
            summary,
            [{"Tactique": k, "Non couvertes": v} for k, v in uncovered_tactics.items()],
            "Techniques non couvertes par tactique",
            29,
            0,
        )
        write_small_analytic_table(
            workbook,
            summary,
            29,
            8,
            "Top priorités à traiter",
            [
                {
                    "ID": item.technique.attack_id,
                    "Technique": item.technique.name,
                    "Score": item.priority_score,
                    "Statut": item.status,
                }
                for item in sorted(coverage_result.coverage, key=lambda value: value.priority_score, reverse=True)
                if item.status != "exact"
            ][:7],
            6,
        )
        sheet = workbook.add_sheet("Couverture")
        create_excel_table(
            workbook,
            sheet,
            [
                {
                    "id": item.technique.attack_id,
                    "name": item.technique.name,
                    "tactic": ", ".join(item.technique.tactics) or "N/A",
                    "occurrences": item.occurrences,
                    "status": {"exact": "✓ Covered", "partial": "⚠ Partially covered", "none": "✗ Not covered"}[
                        item.status
                    ],
                    "exact": ", ".join(item.exact_rules),
                    "related": ", ".join(item.hierarchical_rules),
                    "rules": len(item.exact_rules) + len(item.hierarchical_rules),
                    "score": item.priority_score,
                    "priority": item.priority,
                }
                for item in coverage_result.coverage
            ],
            0,
            0,
            [
                ExcelColumn("id", "Technique ID"),
                ExcelColumn("name", "Name"),
                ExcelColumn("tactic", "Tactic"),
                ExcelColumn("occurrences", "Occurrences"),
                ExcelColumn("status", "Coverage"),
                ExcelColumn("exact", "Exact rules", 35),
                ExcelColumn("related", "Parent/child rules", 35),
                ExcelColumn("rules", "Rule count"),
                ExcelColumn("score", "Priority score"),
                ExcelColumn("priority", "Odysafe priority"),
            ],
        )
        if coverage_result.coverage:
            green = workbook.xlsxwriter_workbook.add_format({"bg_color": "#E8F5E9", "font_color": "#2E7D32"})
            orange = workbook.xlsxwriter_workbook.add_format({"bg_color": "#FFF3E0", "font_color": "#9A5B00"})
            red = workbook.xlsxwriter_workbook.add_format({"bg_color": "#FFEBEE", "font_color": "#C62828"})
            for text, fmt in (("✓", green), ("⚠", orange), ("✗", red)):
                sheet.worksheet.conditional_format(
                    1,
                    4,
                    len(coverage_result.coverage),
                    4,
                    {"type": "text", "criteria": "containing", "value": text, "format": fmt},
                )
            sheet.worksheet.conditional_format(
                1, 8, len(coverage_result.coverage), 8, {"type": "data_bar", "bar_color": "#3E78B2"}
            )
        if coverage_result.include_rules:
            rules = workbook.add_sheet("Règles Sigma")
            create_excel_table(
                workbook,
                rules,
                [
                    {
                        "path": item.path,
                        "id": item.rule_id or "N/A",
                        "title": item.title,
                        "status": item.status,
                        "level": item.level,
                        "tags": ", ".join(item.attack_tags),
                        "errors": ", ".join(item.parse_errors),
                    }
                    for item in coverage_result.sigma_rules
                ],
                0,
                0,
                [
                    ExcelColumn("path", "Path", 45),
                    ExcelColumn("id", "Rule ID"),
                    ExcelColumn("title", "Title", 35),
                    ExcelColumn("status", "Status"),
                    ExcelColumn("level", "Level"),
                    ExcelColumn("tags", "ATT&CK tags", 25),
                    ExcelColumn("errors", "Parse errors", 35),
                ],
            )
        write_meta_sheet(
            workbook,
            build_provenance(
                attack_version=coverage_result.attack_version,
                stix_version=coverage_result.attack_stix_version,
                attack_bundle_path=coverage_result.attack_bundle_path,
                attack_bundle_sha256=coverage_result.attack_bundle_sha256,
                command=command,
                input_hashes=coverage_result.input_hashes,
            ),
        )
    return output_path
