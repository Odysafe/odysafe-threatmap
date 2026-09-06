"""Consistent, auditable provenance metadata for generated workbooks."""

from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from odysafe_threatmap import __version__
from odysafe_threatmap.config.loader import compute_embedded_config_hash


def package_version(package: str) -> str:
    """Return an installed distribution version without hiding absence as N/A."""
    try:
        return version(package)
    except PackageNotFoundError:
        return "Not installed"


def build_provenance(
    *,
    attack_version: str | None,
    stix_version: str,
    attack_bundle_path: str,
    attack_bundle_sha256: str,
    command: str,
    input_hashes: dict[str, str] | None = None,
    input_note: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the shared `_Meta` record and include each input digest separately."""
    hashes = dict(sorted((input_hashes or {}).items()))
    metadata: dict[str, Any] = {
        "odysafe_threatmap_version": __version__,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "attack_version": attack_version or "Not declared by bundle",
        "attack_stix_version": stix_version,
        "attack_bundle_path": attack_bundle_path,
        "attack_bundle_sha256": attack_bundle_sha256,
        "attack_source_type": "Local MITRE CTI Enterprise ATT&CK STIX bundle",
        "attack_source_ref": attack_bundle_path,
        "mitreattack_python_version": package_version("mitreattack-python"),
        "iocsearcher_version": package_version("iocsearcher"),
        "txt2stix_version": package_version("txt2stix"),
        "input_hashes": "; ".join(f"{name}={digest}" for name, digest in hashes.items())
        or input_note
        or "No file input",
        "config_hash_or_version": compute_embedded_config_hash(),
        "offline_mode": True,
        "command": command,
    }
    metadata.update({f"input_sha256:{name}": digest for name, digest in hashes.items()})
    metadata.update(extra or {})
    return metadata
