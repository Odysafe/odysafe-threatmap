"""Excel composition for the Report to CTI Bundle module."""

from pathlib import Path

from odysafe_threatmap import __version__
from odysafe_threatmap.application.report_bundle import ReportBundleResult
from odysafe_threatmap.domain.scoring import interpret_cti_density
from odysafe_threatmap.exporters.excel.dashboard import (
    add_dashboard_bar_chart,
    write_dashboard_header,
    write_info_banner,
    write_kpi_cards,
    write_small_analytic_table,
    write_warning_banner,
)
from odysafe_threatmap.exporters.excel.provenance import build_provenance
from odysafe_threatmap.exporters.excel.sheets.actors_campaigns_sheet import write_actors_campaigns_sheet
from odysafe_threatmap.exporters.excel.sheets.associated_groups_sheet import write_associated_groups_sheet
from odysafe_threatmap.exporters.excel.sheets.detection_sheet import write_detection_sheet
from odysafe_threatmap.exporters.excel.sheets.ioc_summary_sheet import write_ioc_summary_sheet
from odysafe_threatmap.exporters.excel.sheets.iocs_sheet import write_iocs_sheet
from odysafe_threatmap.exporters.excel.sheets.meta_sheet import write_meta_sheet
from odysafe_threatmap.exporters.excel.sheets.mitigations_sheet import write_mitigations_sheet
from odysafe_threatmap.exporters.excel.sheets.report_sheet import write_report_sheet
from odysafe_threatmap.exporters.excel.sheets.summary_sheet import write_summary_sheet
from odysafe_threatmap.exporters.excel.sheets.tactic_coverage_sheet import write_tactic_coverage_sheet
from odysafe_threatmap.exporters.excel.sheets.ttps_sheet import write_ttps_sheet
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook


def write_report_bundle_workbook(output_path: Path, result: ReportBundleResult, command: str) -> Path:
    """Write all Module A sheets in the required order and return the output path."""
    density = interpret_cti_density(result.cti_density)
    density_display = (
        f"{result.cti_density:.1f}\nobservations / 1,000 words" if result.cti_density is not None else "N/A"
    )
    metadata = {
        "inputs": [result.report_metadata.filename],
        "hashes": {result.report_metadata.filename: result.report_metadata.sha256},
        "parameters": {"command": command},
        "versions": {"odysafe-threatmap": __version__},
        "attack_dataset": {
            "version": result.attack_version,
            "path": result.attack_bundle_path,
            "sha256": result.attack_bundle_sha256,
        },
    }
    with ExcelWorkbook(output_path, metadata=metadata) as workbook:
        summary = write_summary_sheet(workbook, {}, [])
        write_dashboard_header(
            workbook,
            summary,
            "Rapport → CTI Bundle",
            f"{result.report_metadata.name} • ATT&CK {result.attack_version or 'N/A'} • Mode offline",
        )
        summary.worksheet.write(
            5, 0, f"IOCs uniques\n{len(result.extraction_result.indicators)}", workbook.theme.subtitle_format
        )
        write_kpi_cards(
            workbook,
            summary,
            {
                "IOCs uniques": len(result.extraction_result.indicators),
                "Occurrences IOC": sum(item.occurrences for item in result.extraction_result.indicators),
                "TTPs uniques": len(result.extraction_result.ttps),
                "TTPs ATT&CK validées": sum(item.validated for item in result.extraction_result.ttps),
                "Acteurs/campagnes explicitement mentionnés": len(result.detected_actors),
                "CTI Observation Density": density_display,
            },
        )
        write_info_banner(workbook, summary, 9, f"{density.label} — {density.explanation}")
        ioc_counts: dict[str, int] = {}
        for indicator in result.extraction_result.indicators:
            ioc_counts[indicator.type] = ioc_counts.get(indicator.type, 0) + 1
        add_dashboard_bar_chart(
            workbook,
            summary,
            [{"Type IOC": key, "Nombre": value} for key, value in sorted(ioc_counts.items())],
            "Répartition des IOCs par type",
            11,
            0,
        )
        ttp_rows = [
            {
                "TTP": f"{item.attack_id} — {item.name}",
                "Occurrences": next(
                    (
                        extracted.occurrences
                        for extracted in result.extraction_result.ttps
                        if extracted.attack_id == item.attack_id
                    ),
                    0,
                ),
            }
            for item in result.techniques
        ]
        add_dashboard_bar_chart(
            workbook,
            summary,
            sorted(
                ttp_rows,
                key=lambda item: item["Occurrences"] if isinstance(item["Occurrences"], int) else 0,
                reverse=True,
            )[:10],
            "Top TTPs par occurrences",
            11,
            7,
        )
        coverage = [
            {"Tactic": tactic, "Count": sum(tactic in item.tactics for item in result.techniques)}
            for tactic in sorted({tactic for item in result.techniques for tactic in item.tactics})
        ]
        if coverage:
            add_dashboard_bar_chart(
                workbook,
                summary,
                [{"Tactique": item["Tactic"], "Nombre": item["Count"]} for item in coverage],
                "Couverture tactique",
                29,
                0,
            )
        groups = sorted(result.associated_groups, key=lambda item: (-len(item.common_technique_ids), item.actor.name))[
            :5
        ]
        add_dashboard_bar_chart(
            workbook,
            summary,
            [{"Groupe": item.actor.name, "TTPs communes": len(item.common_technique_ids)} for item in groups],
            "Top groupes par recouvrement",
            29,
            7,
        )
        write_small_analytic_table(
            workbook,
            summary,
            47,
            0,
            "Top TTPs",
            [
                {
                    "ID": item.attack_id,
                    "Technique": item.name,
                    "Occurrences": next(
                        (
                            value.occurrences
                            for value in result.extraction_result.ttps
                            if value.attack_id == item.attack_id
                        ),
                        0,
                    ),
                    "Tactique": ", ".join(item.tactics),
                }
                for item in result.techniques[:6]
            ],
            6,
        )
        write_small_analytic_table(
            workbook,
            summary,
            47,
            8,
            "Top groupes",
            [
                {
                    "Rang": index,
                    "Groupe": item.actor.name,
                    "TTPs communes": len(item.common_technique_ids),
                    "Recouvrement": f"{item.overlap_percent:.1f} %",
                }
                for index, item in enumerate(groups, 1)
            ],
            6,
        )
        if groups:
            write_warning_banner(workbook, summary, 58, "Corrélation de TTPs — ne constitue pas une attribution.")
        if result.report_metadata.word_count < 100:
            write_warning_banner(
                workbook,
                summary,
                56,
                "Very short report — normalized density can be volatile and should be interpreted cautiously.",
            )
        write_report_sheet(
            workbook, result.report_metadata, result.extraction_result, len(result.detected_actors), result.cti_density
        )
        write_ioc_summary_sheet(workbook, result.extraction_result.indicators)
        write_iocs_sheet(workbook, result.extraction_result.indicators)
        write_ttps_sheet(workbook, result.techniques, result.extraction_result, result.technique_statuses)
        write_tactic_coverage_sheet(workbook, result.techniques)
        write_detection_sheet(workbook, result.techniques)
        write_mitigations_sheet(workbook, result.techniques)
        write_associated_groups_sheet(workbook, result.associated_groups)
        write_actors_campaigns_sheet(workbook, result.detected_actors)
        write_meta_sheet(
            workbook,
            build_provenance(
                attack_version=result.attack_version,
                stix_version=result.attack_stix_version,
                attack_bundle_path=result.attack_bundle_path,
                attack_bundle_sha256=result.attack_bundle_sha256,
                command=command,
                input_hashes={result.report_metadata.filename: result.report_metadata.sha256},
                extra={
                    "cti_density_formula": ("(IOC occurrences + explicit TTP occurrences) / report word count × 1,000"),
                    "cti_density_counting_basis": "Occurrences, not unique values",
                    "cti_density_unit": "explicit CTI observations / 1,000 words",
                    "cti_density_interpretation": density.label,
                    "cti_density_disclaimer": (
                        "Not a danger, confidence, criticality, attack-probability, or report-quality score"
                    ),
                },
            ),
        )
    return output_path
