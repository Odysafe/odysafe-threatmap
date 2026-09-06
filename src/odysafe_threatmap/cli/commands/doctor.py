"""Complete local, offline project diagnostics."""

import sys
import tempfile
from importlib.metadata import PackageNotFoundError, version
from importlib.resources import files
from pathlib import Path

from rich.console import Console

from odysafe_threatmap.config.loader import (
    compute_embedded_config_hash,
    load_actor_metadata,
    load_priority_thresholds,
    load_tactic_impact,
)
from odysafe_threatmap.domain.exceptions import AttackDataError
from odysafe_threatmap.exporters.excel.workbook import ExcelWorkbook
from odysafe_threatmap.infrastructure.attack.index_cache import is_cache_valid
from odysafe_threatmap.infrastructure.attack.loader import load_attack_data
from odysafe_threatmap.infrastructure.attack.repository import AttackRepositoryImpl
from odysafe_threatmap.infrastructure.extraction.txt2stix_adapter import load_offline_config
from odysafe_threatmap.storage.manifest import load_manifest
from odysafe_threatmap.storage.paths import get_cache_db_path


def _dependency_version(package: str) -> str | None:
    try:
        return version(package)
    except PackageNotFoundError:
        return None


def run_doctor(console: Console | None = None) -> int:
    """Run offline diagnostics and return 0, 1, or 2 for OK, warning, or error."""
    output = console or Console()
    status = 0
    if sys.version_info < (3, 11):
        output.print("✗ Python 3.11 or newer is required.")
        status = 2
    else:
        output.print(f"✓ Python {sys.version.split()[0]}")
    for package in (
        "mitreattack-python",
        "iocsearcher",
        "txt2stix",
        "XlsxWriter",
        "openpyxl",
        "pydantic",
        "PyYAML",
    ):
        installed = _dependency_version(package)
        if installed:
            output.print(f"✓ {package} {installed}")
        else:
            output.print(f"✗ Required dependency missing: {package}")
            status = 2
    manifest = load_manifest()
    if manifest is None or not manifest.bundle_path.is_file():
        output.print("⚠ No local MITRE ATT&CK data is installed.")
        status = max(status, 1)
    else:
        output.print("✓ Local MITRE ATT&CK data is installed.")
        try:
            attack_data = load_attack_data(manifest.bundle_path)
            repository = AttackRepositoryImpl(manifest.bundle_path)
            capabilities = repository.get_capabilities()
            output.print("✓ STIX 2.0 Enterprise bundle")
            output.print("✓ MitreAttackData load")
            output.print(
                "✓ Technique lookup"
                if attack_data.get_techniques(remove_revoked_deprecated=True)
                else "⚠ No active techniques"
            )
            output.print(
                "✓ Group lookup" if attack_data.get_groups(remove_revoked_deprecated=True) else "⚠ No active groups"
            )
            output.print(
                "✓ Matrix/tactics" if capabilities.matrices and capabilities.tactics else "⚠ Matrix/tactics unavailable"
            )
            output.print(
                "✓ Mitigation relationship capability" if capabilities.mitigations else "ℹ Mitigations unavailable"
            )
            output.print(
                "✓ Detection strategy capability"
                if capabilities.detection_strategies
                else "ℹ Detection strategies unavailable; legacy detection may be used"
            )
            output.print(
                "✓ Data component capability" if capabilities.data_components else "ℹ Data components unavailable"
            )
        except AttackDataError as error:
            output.print(f"✗ ATT&CK bundle parsing failed: {error}")
            status = 2
        if is_cache_valid(get_cache_db_path(create=False), manifest.sha256):
            output.print("✓ ATT&CK cache is present and valid.")
        else:
            output.print("⚠ ATT&CK cache is absent or invalid.")
            status = max(status, 1)
    defaults = files("odysafe_threatmap.config").joinpath("defaults")
    try:
        load_actor_metadata(Path(str(defaults.joinpath("actor_metadata.yaml"))))
        load_tactic_impact(Path(str(defaults.joinpath("tactic_impact.yaml"))))
        load_priority_thresholds(Path(str(defaults.joinpath("priorities.yaml"))))
        load_offline_config(Path(str(defaults.joinpath("txt2stix_offline.yaml"))))
        output.print("✓ Local configuration and txt2stix offline policy are valid.")
        output.print(f"✓ Configuration hash: {compute_embedded_config_hash()}")
    except (OSError, ValueError) as error:
        output.print(f"✗ Configuration validation failed: {error}")
        status = 2
    try:
        with tempfile.TemporaryDirectory(prefix="odysafe-doctor-") as directory:
            path = Path(directory) / "write-test.xlsx"
            with ExcelWorkbook(path) as workbook:
                workbook.write_title(workbook.add_sheet("Test"), 0, 0, "Offline write test")
        output.print("✓ Excel output can be written.")
    except OSError as error:
        output.print(f"✗ Excel write test failed: {error}")
        status = 2
    try:
        from mitreattack.navlayers import Layer

        if Layer(name="Doctor", domain="enterprise-attack").to_dict() is None:
            raise ValueError("Navigator layer initialization failed.")
        output.print("✓ ATT&CK Navigator support is available.")
    except (ImportError, ValueError) as error:
        output.print(f"✗ ATT&CK Navigator is unavailable: {error}")
        status = 2
    return status


def doctor() -> None:
    """Run diagnostics and expose their status through the CLI exit code."""
    raise SystemExit(run_doctor())
