"""Installation of validated local ATT&CK bundles."""

import json
import os
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from odysafe_threatmap.domain.exceptions import AttackDataInvalidError
from odysafe_threatmap.infrastructure.attack.capabilities import (
    CAPABILITY_SCHEMA_VERSION,
    mitreattack_python_version,
)
from odysafe_threatmap.infrastructure.attack.index_cache import CACHE_SCHEMA_VERSION, build_cache
from odysafe_threatmap.infrastructure.attack.metadata import compute_bundle_metadata
from odysafe_threatmap.storage.manifest import AttackManifest, save_manifest
from odysafe_threatmap.storage.paths import BUNDLE_FILENAME, get_cache_db_path


def _directory_name(version: str | None) -> str:
    """Return a safe data directory name without changing the displayed version."""
    if version is None:
        return "unknown"
    sanitized = "".join(character for character in version if character.isalnum() or character in ".-_")
    return sanitized or "unknown"


def install_bundle(
    source_path: Path,
    destination_dir: Path,
    *,
    cache_db_path: Path | None = None,
    manifest_path: Path | None = None,
    source_kind: str = "local-file",
    source_url: str | None = None,
    source_ref: str | None = None,
    attack_release: str | None = None,
    requested_release: str | None = None,
    resolved_release: str | None = None,
    attack_release_provenance: str = "unknown",
    downloaded_at_utc: datetime | None = None,
    progress: Callable[[str], None] | None = None,
) -> AttackManifest:
    """Validate, atomically install, index, and record a local ATT&CK bundle."""
    source = Path(source_path)
    if not source.is_file():
        raise AttackDataInvalidError(f"ATT&CK bundle does not exist: {source}")
    if progress is not None:
        progress("Validating the STIX bundle")
    metadata = compute_bundle_metadata(source)
    snapshot_label = attack_release or source_ref or metadata["version"] or "snapshot"
    target_directory = Path(destination_dir) / _directory_name(str(snapshot_label)) / str(metadata["sha256"])[:16]
    target_directory.mkdir(parents=True, exist_ok=True)
    destination = target_directory / BUNDLE_FILENAME
    if progress is not None:
        progress("Installing the validated ATT&CK bundle")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".enterprise-attack-", dir=target_directory)
    try:
        with os.fdopen(descriptor, "wb") as temporary_file, source.open("rb") as source_file:
            shutil.copyfileobj(source_file, temporary_file)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_name, destination)
    except OSError as error:
        Path(temporary_name).unlink(missing_ok=True)
        raise AttackDataInvalidError(f"Unable to install ATT&CK bundle: {error}") from error
    manifest = AttackManifest(
        bundle_path=destination.resolve(),
        version=metadata["version"],
        sha256=str(metadata["sha256"]),
        spec_version=str(metadata["spec_version"]),
        installed_at=datetime.now(timezone.utc),
        cache_version=CACHE_SCHEMA_VERSION,
        source_kind=source_kind,
        source_url=source_url,
        source_ref=source_ref,
        attack_release=attack_release,
        requested_release=requested_release,
        resolved_release=resolved_release,
        attack_release_provenance=attack_release_provenance,
        stix_version=str(metadata["spec_version"]),
        downloaded_at_utc=downloaded_at_utc,
        mitreattack_python_version=mitreattack_python_version(),
        capability_schema_version=CAPABILITY_SCHEMA_VERSION,
        capabilities=json.loads(json.dumps(asdict(metadata["capabilities"]))),
    )
    if progress is not None:
        progress("Building the local ATT&CK index")
    build_cache(destination, cache_db_path or get_cache_db_path())
    if progress is not None:
        progress("Activating the ATT&CK snapshot")
    save_manifest(manifest, manifest_path)
    return manifest
