"""Excel composition for multi-report aggregation."""

from collections import Counter
from pathlib import Path

from odysafe_threatmap import __version__
from odysafe_threatmap.application.multi_report import AggregateResult
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


def _table(
    workbook: ExcelWorkbook,
    name: str,
    rows: list[dict[str, object]],
    columns: list[ExcelColumn],
    title: str | None = None,
) -> None:
    sheet = workbook.add_sheet(name)
    row = 0
    if title:
        workbook.write_subtitle(sheet, row, 0, title)
        row = 2
    create_excel_table(workbook, sheet, rows, row, 0, columns)


def _input_hashes(result: AggregateResult) -> dict[str, str]:
    """Return a digest for every received report, including exact duplicates."""
    hashes = {item.filename: item.sha256 for item in result.reports}
    by_filename = {item.filename: item.sha256 for item in result.reports}
    for duplicate in result.duplicate_paths:
        original = result.duplicate_of.get(str(duplicate))
        if original and original in by_filename:
            hashes[duplicate.name] = by_filename[original]
    return hashes


def build_aggregate_workbook(aggregate_result: AggregateResult, output_path: Path, command: str) -> Path:
    """Write the Module F workbook in the required sheet order."""
    input_hashes = _input_hashes(aggregate_result)
    metadata = {
        "inputs": [item.filename for item in aggregate_result.reports],
        "hashes": input_hashes,
        "parameters": {"command": command},
        "versions": {"odysafe-threatmap": __version__},
        "attack_dataset": {
            "version": aggregate_result.attack_version,
            "path": aggregate_result.attack_bundle_path,
            "sha256": aggregate_result.attack_bundle_sha256,
        },
    }
    with ExcelWorkbook(output_path, metadata=metadata) as workbook:
        false_count = sum(item.corroboration_status == "false" for item in aggregate_result.corroboration)
        summary = workbook.add_sheet("Synthèse")
        unique_reports = len({item.sha256 for item in aggregate_result.reports})
        primary_sources = len({item.primary_source_id for item in aggregate_result.reports if item.primary_source_id})
        write_dashboard_header(
            workbook,
            summary,
            "Agrégation multi-rapports",
            f"{len(aggregate_result.reports)} rapports • ATT&CK {aggregate_result.attack_version or 'N/A'} • Mode offline",
        )
        write_kpi_cards(
            workbook,
            summary,
            {
                "Rapports analysés": len(aggregate_result.reports),
                "Rapports uniques": unique_reports,
                "IOCs uniques": len(aggregate_result.indicators),
                "TTPs uniques": len(aggregate_result.techniques),
                "Sources primaires": primary_sources,
                "Alertes corroboration": false_count,
            },
        )
        top_iocs = sorted(aggregate_result.indicators, key=lambda item: len(item.reports), reverse=True)[:10]
        top_ttps = sorted(aggregate_result.techniques, key=lambda item: len(item.reports), reverse=True)[:10]
        source_counts = Counter(item.source_name or "N/A" for item in aggregate_result.reports)
        status_counts = Counter(item.corroboration_status for item in aggregate_result.corroboration)
        add_dashboard_bar_chart(
            workbook,
            summary,
            [{"IOC": item.indicator.normalized_value, "Rapports": len(item.reports)} for item in top_iocs],
            "Top IOCs récurrents",
            11,
            0,
        )
        add_dashboard_bar_chart(
            workbook,
            summary,
            [
                {"TTP": f"{item.technique.attack_id} — {item.technique.name}", "Rapports": len(item.reports)}
                for item in top_ttps
            ],
            "Top TTPs",
            11,
            7,
        )
        add_dashboard_bar_chart(
            workbook,
            summary,
            [{"Source": k, "Rapports": v} for k, v in source_counts.items()],
            "Sources primaires",
            29,
            0,
            horizontal=False,
        )
        add_dashboard_pie_chart(
            workbook,
            summary,
            [{"Statut": k, "Éléments": v} for k, v in status_counts.items()],
            "Statuts de corroboration",
            29,
            7,
        )
        write_small_analytic_table(
            workbook,
            summary,
            47,
            0,
            "Alertes de corroboration",
            [
                {
                    "Élément": item.item_id,
                    "Type": item.item_type,
                    "Rapports": item.reports_count,
                    "Sources": item.primary_sources_count,
                }
                for item in aggregate_result.corroboration[:6]
            ],
            6,
        )
        _table(
            workbook,
            "Rapports",
            [
                {
                    "file": item.filename,
                    "hash": item.sha256,
                    "source": item.source_name or "N/A",
                    "primary": item.primary_source_id or "N/A",
                    "words": item.extraction.word_count,
                    "iocs": len(item.extraction.indicators),
                    "ttps": len(item.extraction.ttps),
                    "warning": item.warning or "",
                }
                for item in aggregate_result.reports
            ]
            + [
                {
                    "file": path.name,
                    "hash": next(
                        (
                            item.sha256
                            for item in aggregate_result.reports
                            if item.filename == aggregate_result.duplicate_of.get(str(path))
                        ),
                        "N/A",
                    ),
                    "source": "N/A",
                    "primary": "N/A",
                    "words": "N/A",
                    "iocs": "N/A",
                    "ttps": "N/A",
                    "warning": f"Exact duplicate of {aggregate_result.duplicate_of.get(str(path), 'N/A')}",
                }
                for path in aggregate_result.duplicate_paths
            ],
            [
                ExcelColumn("file", "File"),
                ExcelColumn("hash", "SHA-256", 50),
                ExcelColumn("source", "Source"),
                ExcelColumn("primary", "Primary source"),
                ExcelColumn("words", "Words"),
                ExcelColumn("iocs", "IOCs"),
                ExcelColumn("ttps", "TTPs"),
                ExcelColumn("warning", "Warnings", 35),
            ],
        )
        _table(
            workbook,
            "IOCs",
            [
                {
                    "type": item.indicator.type,
                    "value": item.indicator.normalized_value,
                    "reports": len(item.reports),
                    "names": ", ".join(item.reports),
                    "sources": item.primary_sources_count,
                    "status": item.corroboration_status,
                }
                for item in aggregate_result.indicators
            ],
            [
                ExcelColumn("type", "Type"),
                ExcelColumn("value", "Value", 45),
                ExcelColumn("reports", "Report count"),
                ExcelColumn("names", "Reports", 35),
                ExcelColumn("sources", "Primary sources"),
                ExcelColumn("status", "Corroboration"),
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
                    "reports": len(item.reports),
                    "names": ", ".join(item.reports),
                    "sources": ", ".join(item.primary_sources) or "N/A",
                    "status": item.corroboration_status,
                }
                for item in aggregate_result.techniques
            ],
            [
                ExcelColumn("id", "Technique ID"),
                ExcelColumn("name", "Name"),
                ExcelColumn("tactic", "Tactics"),
                ExcelColumn("reports", "Report count"),
                ExcelColumn("names", "Reports", 35),
                ExcelColumn("sources", "Primary sources", 28),
                ExcelColumn("status", "Corroboration"),
            ],
        )
        false_items = [item for item in aggregate_result.corroboration if item.corroboration_status == "false"]
        _table(
            workbook,
            "Fausse corroboration",
            [
                {
                    "id": item.item_id,
                    "type": item.item_type,
                    "reports": item.reports_count,
                    "sources": item.primary_sources_count,
                }
                for item in false_items
            ],
            [
                ExcelColumn("id", "Item ID", 45),
                ExcelColumn("type", "Item type"),
                ExcelColumn("reports", "Reports"),
                ExcelColumn("sources", "Primary sources"),
            ],
            "False corroboration: multiple reports depend on one primary source.",
        )
        write_meta_sheet(
            workbook,
            build_provenance(
                attack_version=aggregate_result.attack_version,
                stix_version=aggregate_result.attack_stix_version,
                attack_bundle_path=aggregate_result.attack_bundle_path,
                attack_bundle_sha256=aggregate_result.attack_bundle_sha256,
                command=command,
                input_hashes=input_hashes,
            ),
        )
    return output_path
