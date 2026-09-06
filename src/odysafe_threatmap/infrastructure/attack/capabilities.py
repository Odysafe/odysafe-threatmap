"""Runtime ATT&CK format, library, and bundle capability detection."""

import json
from dataclasses import dataclass
from enum import StrEnum
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from mitreattack.stix20 import MitreAttackData

from odysafe_threatmap.domain.exceptions import AttackDataInvalidError

CAPABILITY_SCHEMA_VERSION = "1"
KNOWN_OBJECT_TYPES = {
    "attack-pattern",
    "campaign",
    "course-of-action",
    "identity",
    "intrusion-set",
    "malware",
    "marking-definition",
    "relationship",
    "tool",
    "x-mitre-analytic",
    "x-mitre-asset",
    "x-mitre-collection",
    "x-mitre-data-component",
    "x-mitre-data-source",
    "x-mitre-detection-strategy",
    "x-mitre-matrix",
    "x-mitre-tactic",
}
REQUIRED_LIBRARY_METHODS = (
    "get_object_by_attack_id",
    "get_object_by_stix_id",
    "get_groups",
    "get_techniques",
    "get_campaigns",
    "get_mitigations",
    "get_matrices",
    "get_tactics",
    "get_related",
    "get_campaigns_attributed_to_group",
)


class CompatibilityState(StrEnum):
    SUPPORTED = "SUPPORTED"
    SUPPORTED_WITH_LIMITATIONS = "SUPPORTED_WITH_LIMITATIONS"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True, slots=True)
class AttackCapabilities:
    stix_version: str
    domain: str
    compatibility: CompatibilityState
    object_types: tuple[str, ...]
    unknown_object_types: tuple[str, ...]
    relationship_types: tuple[str, ...]
    attack_spec_versions: tuple[str, ...]
    matrices: bool
    tactics: bool
    techniques: bool
    groups: bool
    software: bool
    campaigns: bool
    mitigations: bool
    data_sources_legacy: bool
    data_components: bool
    detection_strategies: bool
    analytics: bool
    detects_relationships: bool
    subtechnique_relationships: bool
    attributed_to_relationships: bool
    detection_route: str | None
    limitations: tuple[str, ...]


def mitreattack_python_version() -> str:
    try:
        return version("mitreattack-python")
    except PackageNotFoundError:
        return "unknown"


def verify_library_capabilities() -> tuple[str, ...]:
    """Fail early when the installed library lacks operations Odysafe requires."""
    missing = tuple(name for name in REQUIRED_LIBRARY_METHODS if not callable(getattr(MitreAttackData, name, None)))
    if missing:
        raise AttackDataInvalidError(
            "The installed mitreattack-python is incompatible; missing APIs: " + ", ".join(missing)
        )
    return REQUIRED_LIBRARY_METHODS


def read_bundle_document(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AttackDataInvalidError(f"Unable to parse ATT&CK JSON: {error}") from error
    if not isinstance(value, dict):
        raise AttackDataInvalidError("The ATT&CK document must be a JSON object.")
    return value


def detect_bundle_capabilities(path: Path) -> AttackCapabilities:
    """Inspect explicit STIX structure without guessing from ATT&CK release numbers."""
    bundle = read_bundle_document(path)
    if bundle.get("type") != "bundle":
        raise AttackDataInvalidError("The file is valid JSON but is not a STIX bundle.")
    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects:
        raise AttackDataInvalidError("The STIX bundle contains no Enterprise ATT&CK objects.")
    object_maps = [item for item in objects if isinstance(item, dict)]
    stix_versions = {str(item.get("spec_version")) for item in object_maps if item.get("spec_version")}
    top_level = bundle.get("spec_version")
    if isinstance(top_level, str):
        stix_versions.add(top_level)
    if "2.1" in stix_versions:
        raise AttackDataInvalidError(
            "ATT&CK STIX 2.1 format detected. This Odysafe release currently uses the mitreattack-python STIX 2.0 adapter."
        )
    if stix_versions != {"2.0"}:
        shown = ", ".join(sorted(stix_versions)) or "missing"
        raise AttackDataInvalidError(f"Unsupported or inconsistent STIX version: {shown}.")
    types = {str(item.get("type")) for item in object_maps if item.get("type")}
    domains = {
        str(domain) for item in object_maps for domain in item.get("x_mitre_domains", []) if isinstance(domain, str)
    }
    if "enterprise-attack" not in domains:
        raise AttackDataInvalidError("The STIX bundle is not an Enterprise ATT&CK dataset.")
    relationships = [item for item in object_maps if item.get("type") == "relationship"]
    relationship_types = {str(item.get("relationship_type")) for item in relationships if item.get("relationship_type")}
    attack_specs = {
        str(item["x_mitre_attack_spec_version"]) for item in object_maps if item.get("x_mitre_attack_spec_version")
    }
    detects = "detects" in relationship_types
    strategies = "x-mitre-detection-strategy" in types
    analytics = "x-mitre-analytic" in types
    components = "x-mitre-data-component" in types
    if strategies and analytics:
        route = "detection-strategy"
    elif components and detects:
        route = "legacy-data-component"
    else:
        route = None
    limitations = () if route else ("No supported ATT&CK detection representation is present.",)
    return AttackCapabilities(
        stix_version="2.0",
        domain="enterprise-attack",
        compatibility=CompatibilityState.SUPPORTED if route else CompatibilityState.SUPPORTED_WITH_LIMITATIONS,
        object_types=tuple(sorted(types)),
        unknown_object_types=tuple(sorted(types - KNOWN_OBJECT_TYPES)),
        relationship_types=tuple(sorted(relationship_types)),
        attack_spec_versions=tuple(sorted(attack_specs)),
        matrices="x-mitre-matrix" in types,
        tactics="x-mitre-tactic" in types,
        techniques="attack-pattern" in types,
        groups="intrusion-set" in types,
        software=bool(types & {"malware", "tool"}),
        campaigns="campaign" in types,
        mitigations="course-of-action" in types,
        data_sources_legacy="x-mitre-data-source" in types,
        data_components=components,
        detection_strategies=strategies,
        analytics=analytics,
        detects_relationships=detects,
        subtechnique_relationships="subtechnique-of" in relationship_types,
        attributed_to_relationships="attributed-to" in relationship_types,
        detection_route=route,
        limitations=limitations,
    )
