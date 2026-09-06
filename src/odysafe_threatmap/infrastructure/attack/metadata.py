"""Validation and metadata extraction for local STIX bundles."""

import hashlib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from odysafe_threatmap.domain.exceptions import AttackDataInvalidError
from odysafe_threatmap.infrastructure.attack.capabilities import detect_bundle_capabilities, read_bundle_document


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as bundle_file:
        for chunk in iter(lambda: bundle_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _objects(bundle: dict[str, Any]) -> Iterable[dict[str, Any]]:
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise AttackDataInvalidError("The STIX bundle does not contain an objects list.")
    for item in objects:
        if isinstance(item, dict):
            yield item


def _detect_version(bundle: dict[str, Any], objects: Iterable[dict[str, Any]]) -> str | None:
    """Return a dataset release version only when the bundle exposes one."""
    for key in ("x_mitre_version", "attack_version", "version"):
        value = bundle.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for item in objects:
        if item.get("type") in {"x-mitre-collection", "identity"}:
            for key in ("x_mitre_version", "x_mitre_attack_version", "attack_version"):
                value = item.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return None


def _is_enterprise_bundle(objects: Iterable[dict[str, Any]]) -> bool:
    for item in objects:
        domains = item.get("x_mitre_domains", [])
        if isinstance(domains, list) and "enterprise-attack" in domains:
            return True
    return False


def compute_bundle_metadata(bundle_path: Path) -> dict[str, Any]:
    """Validate a local Enterprise ATT&CK STIX 2.0 bundle and return metadata."""
    path = Path(bundle_path)
    if not path.is_file():
        raise AttackDataInvalidError(f"ATT&CK bundle does not exist: {path}")
    bundle = read_bundle_document(path)
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise AttackDataInvalidError("The file is not a STIX bundle.")
    capabilities = detect_bundle_capabilities(path)
    spec_version = capabilities.stix_version
    objects = list(_objects(bundle))
    if not _is_enterprise_bundle(objects):
        raise AttackDataInvalidError("The STIX bundle is not an Enterprise ATT&CK bundle.")
    return {
        "bundle_path": str(path.resolve()),
        "version": _detect_version(bundle, objects),
        "sha256": _sha256(path),
        "spec_version": spec_version,
        "bundle_size_bytes": path.stat().st_size,
        "capabilities": capabilities,
    }
