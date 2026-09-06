"""Excel composition for the Threat Actor Snapshot module."""

from pathlib import Path

from odysafe_threatmap import __version__
from odysafe_threatmap.application.actor_snapshot import ActorSnapshotResult
from odysafe_threatmap.exporters.excel.provenance import build_provenance
from odysafe_threatmap.exporters.excel.sheets.campaigns_sheet import write_campaigns_sheet
from odysafe_threatmap.exporters.excel.sheets.comparison_sheet import write_comparison_sheet
from odysafe_threatmap.exporters.excel.sheets.meta_sheet import write_meta_sheet
from odysafe_threatmap.exporters.excel.sheets.profile_sheet import write_profile_sheet
from odysafe_threatmap.exporters.excel.sheets.software_sheet import write_software_sheet
from odysafe_threatmap.exporters.excel.sheets.summary_sheet_b import write_summary_sheet_b
from odysafe_threatmap.exporters.excel.sheets.tactic_heatmap_sheet import write_tactic_heatmap_sheet
from odysafe_threatmap.exporters.excel.sheets.ttps_sheet_b import write_ttps_sheet_b
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook


def build_actor_workbook(snapshot_result: ActorSnapshotResult, output_path: Path, command: str) -> Path:
    """Write the Module B workbook in its prescribed sheet order."""
    metadata = {
        "inputs": [actor.attack_id for actor in snapshot_result.actors],
        "hashes": {},
        "parameters": {"command": command, "include_campaigns": snapshot_result.options.include_campaigns},
        "versions": {"odysafe-threatmap": __version__},
        "attack_dataset": {
            "version": snapshot_result.attack_version,
            "path": snapshot_result.attack_bundle_path,
            "sha256": snapshot_result.attack_bundle_sha256,
        },
    }
    with ExcelWorkbook(output_path, metadata=metadata) as workbook:
        write_summary_sheet_b(workbook, snapshot_result)
        write_profile_sheet(workbook, snapshot_result)
        write_ttps_sheet_b(workbook, snapshot_result)
        write_software_sheet(workbook, snapshot_result)
        write_campaigns_sheet(workbook, snapshot_result)
        write_tactic_heatmap_sheet(workbook, snapshot_result)
        write_comparison_sheet(workbook, snapshot_result)
        write_meta_sheet(
            workbook,
            build_provenance(
                attack_version=snapshot_result.attack_version,
                stix_version=snapshot_result.attack_stix_version,
                attack_bundle_path=snapshot_result.attack_bundle_path,
                attack_bundle_sha256=snapshot_result.attack_bundle_sha256,
                command=command,
                input_note="Not applicable — input is explicit ATT&CK group identifiers",
            ),
        )
    return output_path
