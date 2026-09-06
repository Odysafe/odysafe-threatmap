"""Persistent metadata for local ATT&CK data and generated outputs."""

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from odysafe_threatmap.domain.exceptions import AttackDataInvalidError
from odysafe_threatmap.storage.paths import get_config_path


class AttackManifest(BaseModel):
    """Metadata needed to locate and validate an installed bundle."""

    model_config = ConfigDict(frozen=True)

    bundle_path: Path
    version: str | None = None
    sha256: str
    spec_version: str
    installed_at: datetime
    cache_version: str
    source_kind: str = "local-file"
    source_url: str | None = None
    source_ref: str | None = None
    attack_release: str | None = None
    requested_release: str | None = None
    resolved_release: str | None = None
    attack_release_provenance: str = "unknown"
    stix_version: str = "2.0"
    downloaded_at_utc: datetime | None = None
    mitreattack_python_version: str = "unknown"
    capability_schema_version: str = "1"
    capabilities: dict[str, Any] = Field(default_factory=dict)


def save_manifest(manifest: AttackManifest, manifest_path: Path | None = None) -> Path:
    """Atomically save an ATT&CK manifest and return its path."""
    destination = manifest_path or get_config_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".attack-manifest-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as temporary_file:
            temporary_file.write(manifest.model_dump_json(indent=2))
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_name, destination)
    except OSError as error:
        Path(temporary_name).unlink(missing_ok=True)
        raise AttackDataInvalidError(f"Unable to save ATT&CK manifest: {error}") from error
    return destination


def load_manifest(manifest_path: Path | None = None) -> AttackManifest | None:
    """Load the active ATT&CK manifest, if it exists."""
    source = manifest_path or get_config_path(create=False)
    if not source.is_file():
        return None
    try:
        return AttackManifest.model_validate_json(source.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise AttackDataInvalidError(f"Unable to load ATT&CK manifest: {error}") from error


def generate_manifest(output_path: Path, metadata: dict[str, Any]) -> Path:
    """Write the technical manifest associated with one generated output."""
    destination = Path(output_path).parent / "manifest.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "inputs": metadata.get("inputs", []),
        "hashes": metadata.get("hashes", {}),
        "parameters": metadata.get("parameters", {}),
        "warnings": metadata.get("warnings", []),
        "outputs": metadata.get("outputs", [str(Path(output_path))]),
        "versions": metadata.get("versions", {}),
        "attack_dataset": metadata.get("attack_dataset", {}),
    }
    descriptor, temporary_name = tempfile.mkstemp(prefix=".manifest-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as temporary_file:
            json.dump(payload, temporary_file, ensure_ascii=False, indent=2, default=str)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_name, destination)
    except OSError as error:
        Path(temporary_name).unlink(missing_ok=True)
        raise AttackDataInvalidError(f"Unable to write output manifest: {error}") from error
    return destination
