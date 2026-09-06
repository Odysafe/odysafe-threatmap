"""Repository interface and implementation for local ATT&CK data."""

from collections.abc import Iterable
from pathlib import Path
from typing import Any, Protocol, cast

from odysafe_threatmap.domain.models import (
    NOT_AVAILABLE,
    ActorRecord,
    AttackTechnique,
    CampaignRecord,
    DataComponentRef,
    DetectionEvidence,
    MitigationRef,
    SoftwareRecord,
)
from odysafe_threatmap.infrastructure.attack.capabilities import AttackCapabilities
from odysafe_threatmap.infrastructure.attack.loader import load_attack_data
from odysafe_threatmap.infrastructure.attack.metadata import compute_bundle_metadata


class AttackRepository(Protocol):
    """Port used by application services to query local ATT&CK data."""

    def get_technique(self, attack_id: str) -> AttackTechnique | None: ...

    def get_technique_status(self, attack_id: str) -> str: ...

    def get_group(self, identifier: str) -> ActorRecord | None: ...

    def get_groups(self) -> list[ActorRecord]: ...

    def get_techniques(self) -> list[AttackTechnique]: ...

    def get_techniques_for_group(self, group_id: str) -> list[AttackTechnique]: ...

    def get_technique_summaries_for_group(self, group_id: str) -> list[AttackTechnique]: ...

    def get_groups_for_technique(self, technique_id: str) -> list[ActorRecord]: ...

    def get_mitigations_for_technique(self, technique_id: str) -> list[MitigationRef]: ...

    def get_data_components_for_technique(self, technique_id: str) -> list[DataComponentRef]: ...

    def get_software_for_group(self, group_id: str) -> list[SoftwareRecord]: ...

    def get_software_summaries_for_group(self, group_id: str) -> list[SoftwareRecord]: ...

    def get_campaigns_for_group(self, group_id: str) -> list[CampaignRecord]: ...

    def get_all_tactics(self) -> list[dict[str, str]]: ...

    def get_version(self) -> str | None: ...

    def get_bundle_sha256(self) -> str: ...

    def get_bundle_path(self) -> str: ...

    def get_capabilities(self) -> AttackCapabilities: ...


def _field(value: Any, name: str, default: Any = None) -> Any:
    return value.get(name, default) if isinstance(value, dict) else getattr(value, name, default)


def _attack_id(value: Any) -> str:
    for reference in _field(value, "external_references", []) or []:
        external_id = _field(reference, "external_id")
        if isinstance(external_id, str):
            return external_id.upper()
    return NOT_AVAILABLE


def _active(value: Any) -> bool:
    return not bool(_field(value, "revoked", False) or _field(value, "x_mitre_deprecated", False))


def _attack_url(value: Any) -> str:
    for reference in _field(value, "external_references", []) or []:
        url = _field(reference, "url")
        if isinstance(url, str) and url:
            return url
    return NOT_AVAILABLE


def _optional_text(value: Any) -> str | None:
    """Convert optional STIX values, including datetimes, to text safely."""
    return str(value) if value is not None else None


def _relationship_objects(entries: Iterable[Any]) -> list[Any]:
    objects: list[Any] = []
    for entry in entries:
        object_value = _field(entry, "object")
        if object_value is not None and _active(object_value):
            objects.append(object_value)
    return objects


class AttackRepositoryImpl:
    """Adapter that isolates mitreattack-python behind domain models."""

    def __init__(self, bundle_path: Path) -> None:
        self._bundle_path = Path(bundle_path).resolve()
        self._metadata = compute_bundle_metadata(self._bundle_path)
        self._data = load_attack_data(self._bundle_path)
        self._direct_relationship_cache: dict[tuple[str, str, str, bool], dict[str, list[Any]]] = {}
        self._technique_cache: dict[str, AttackTechnique | None] = {}
        self._software_cache: dict[str, SoftwareRecord | None] = {}
        self._groups_cache: list[ActorRecord] | None = None
        self._campaign_cache: dict[str, CampaignRecord | None] = {}

    def _direct_related(
        self, source_type: str, relationship_type: str, target_type: str, *, reverse: bool = False
    ) -> dict[str, list[Any]]:
        """Use MitreAttackData's datastore traversal without campaign inheritance."""
        key = (source_type, relationship_type, target_type, reverse)
        if key not in self._direct_relationship_cache:
            self._direct_relationship_cache[key] = cast(
                dict[str, list[Any]],
                self._data.get_related(source_type, relationship_type, target_type, reverse=reverse),
            )
        return self._direct_relationship_cache[key]

    def _direct_targets(self, source_stix_id: str, relationship_type: str, target_types: set[str]) -> list[Any]:
        """Resolve direct targets for one source without materializing the complete ATT&CK graph."""
        targets: list[Any] = []
        for relationship in self._data.src.relationships(source_stix_id, relationship_type, source_only=True):
            if not _active(relationship):
                continue
            target_ref = _field(relationship, "target_ref")
            if not isinstance(target_ref, str) or target_ref.split("--", 1)[0] not in target_types:
                continue
            try:
                target = self._data.get_object_by_stix_id(target_ref)
            except ValueError:
                continue
            if target is not None and _active(target):
                targets.append(target)
        return targets

    def _direct_sources(self, target_stix_id: str, relationship_type: str, source_types: set[str]) -> list[Any]:
        """Resolve direct sources without materializing a bundle-wide relationship map."""
        sources: list[Any] = []
        for relationship in self._data.src.relationships(target_stix_id, relationship_type, target_only=True):
            if not _active(relationship):
                continue
            source_ref = _field(relationship, "source_ref")
            if not isinstance(source_ref, str) or source_ref.split("--", 1)[0] not in source_types:
                continue
            try:
                source = self._data.get_object_by_stix_id(source_ref)
            except ValueError:
                continue
            if source is not None and _active(source):
                sources.append(source)
        return sources

    def _to_technique_summary(self, technique: Any) -> AttackTechnique | None:
        """Normalize fields used by sector analysis without optional relationship enrichment."""
        if not _active(technique):
            return None
        stix_id = _field(technique, "id")
        if not isinstance(stix_id, str):
            return None
        return AttackTechnique(
            attack_id=_attack_id(technique),
            stix_id=stix_id,
            name=str(_field(technique, "name", NOT_AVAILABLE)),
            tactics=tuple(
                str(_field(tactic, "name", NOT_AVAILABLE))
                for tactic in self._data.get_tactics_by_technique(stix_id)
                if _active(tactic)
            ),
            platforms=tuple(str(item) for item in (_field(technique, "x_mitre_platforms", []) or [])),
            description=str(_field(technique, "description", NOT_AVAILABLE)),
            is_subtechnique=bool(_field(technique, "x_mitre_is_subtechnique", False)),
            attack_url=_attack_url(technique),
        )

    @staticmethod
    def _to_software_summary(software: Any) -> SoftwareRecord | None:
        """Normalize software identity fields used by sector results."""
        if not _active(software):
            return None
        stix_id = _field(software, "id")
        if not isinstance(stix_id, str):
            return None
        return SoftwareRecord(
            attack_id=_attack_id(software),
            stix_id=stix_id,
            name=str(_field(software, "name", NOT_AVAILABLE)),
            type=str(_field(software, "type", NOT_AVAILABLE)),
            platforms=tuple(str(value) for value in (_field(software, "x_mitre_platforms", []) or [])),
            description=str(_field(software, "description", NOT_AVAILABLE)),
            attack_url=_attack_url(software),
        )

    def _to_technique(self, technique: Any) -> AttackTechnique | None:
        if not _active(technique):
            return None
        stix_id = _field(technique, "id")
        if not isinstance(stix_id, str):
            return None
        if stix_id in self._technique_cache:
            return self._technique_cache[stix_id]
        tactics = tuple(
            str(_field(tactic, "name", NOT_AVAILABLE))
            for tactic in self._data.get_tactics_by_technique(stix_id)
            if _active(tactic)
        )
        platforms = tuple(str(item) for item in (_field(technique, "x_mitre_platforms", []) or []))
        normalized = AttackTechnique(
            attack_id=_attack_id(technique),
            stix_id=stix_id,
            name=str(_field(technique, "name", NOT_AVAILABLE)),
            tactics=tactics,
            platforms=platforms,
            description=str(_field(technique, "description", NOT_AVAILABLE)),
            is_subtechnique=bool(_field(technique, "x_mitre_is_subtechnique", False)),
            mitigations=tuple(self.get_mitigations_for_technique_by_stix_id(stix_id)),
            data_components=tuple(self.get_data_components_for_technique_by_stix_id(stix_id)),
            detection_evidence=tuple(self.get_detection_evidence_by_stix_id(stix_id, _attack_id(technique))),
            groups_count=len(self._direct_sources(stix_id, "uses", {"intrusion-set"})),
            software_count=len(self._direct_sources(stix_id, "uses", {"malware", "tool"})),
            attack_url=_attack_url(technique),
        )
        self._technique_cache[stix_id] = normalized
        return normalized

    def _to_actor(self, group: Any) -> ActorRecord | None:
        if not _active(group):
            return None
        stix_id = _field(group, "id")
        if not isinstance(stix_id, str):
            return None
        aliases = tuple(str(alias) for alias in (_field(group, "aliases", []) or []))
        motivations = tuple(str(value) for value in (_field(group, "secondary_motivations", []) or []))
        return ActorRecord(
            attack_id=_attack_id(group),
            stix_id=stix_id,
            name=str(_field(group, "name", NOT_AVAILABLE)),
            aliases=aliases,
            description=str(_field(group, "description", NOT_AVAILABLE)),
            first_seen=str(_field(group, "first_seen", NOT_AVAILABLE)),
            last_seen=str(_field(group, "last_seen", NOT_AVAILABLE)),
            resource_level=str(_field(group, "resource_level", NOT_AVAILABLE)),
            primary_motivation=str(_field(group, "primary_motivation", NOT_AVAILABLE)),
            secondary_motivations=motivations,
            attack_url=_attack_url(group),
        )

    def _to_software(self, software: Any) -> SoftwareRecord | None:
        if not _active(software):
            return None
        stix_id = _field(software, "id")
        if not isinstance(stix_id, str):
            return None
        if stix_id in self._software_cache:
            return self._software_cache[stix_id]
        techniques = tuple(
            technique.attack_id
            for value in _relationship_objects(self._data.get_techniques_used_by_software(stix_id))
            if (technique := self._to_technique_summary(value)) is not None
        )
        other_groups = tuple(
            actor.name
            for value in self._direct_sources(stix_id, "uses", {"intrusion-set"})
            if (actor := self._to_actor(value)) is not None
        )
        normalized = SoftwareRecord(
            attack_id=_attack_id(software),
            stix_id=stix_id,
            name=str(_field(software, "name", NOT_AVAILABLE)),
            type=str(_field(software, "type", NOT_AVAILABLE)),
            platforms=tuple(str(value) for value in (_field(software, "x_mitre_platforms", []) or [])),
            description=str(_field(software, "description", NOT_AVAILABLE)),
            techniques=techniques,
            other_groups=other_groups,
            attack_url=_attack_url(software),
        )
        self._software_cache[stix_id] = normalized
        return normalized

    def _to_campaign(self, campaign: Any) -> CampaignRecord | None:
        if not _active(campaign):
            return None
        stix_id = _field(campaign, "id")
        if not isinstance(stix_id, str):
            return None
        if stix_id in self._campaign_cache:
            return self._campaign_cache[stix_id]
        techniques = tuple(
            technique.attack_id
            for value in _relationship_objects(self._data.get_techniques_used_by_campaign(stix_id))
            if (technique := self._to_technique_summary(value)) is not None
        )
        software = tuple(
            record.name
            for value in _relationship_objects(self._data.get_software_used_by_campaign(stix_id))
            if (record := self._to_software_summary(value)) is not None
        )
        normalized = CampaignRecord(
            attack_id=_attack_id(campaign),
            stix_id=stix_id,
            name=str(_field(campaign, "name", NOT_AVAILABLE)),
            first_seen=_optional_text(_field(campaign, "first_seen")),
            last_seen=_optional_text(_field(campaign, "last_seen")),
            description=str(_field(campaign, "description", NOT_AVAILABLE)),
            techniques=techniques,
            software=software,
            attack_url=_attack_url(campaign),
        )
        self._campaign_cache[stix_id] = normalized
        return normalized

    def get_technique(self, attack_id: str) -> AttackTechnique | None:
        """Return an active technique by exact ATT&CK ID."""
        value = self._data.get_object_by_attack_id(attack_id.upper(), "attack-pattern")
        return self._to_technique(value) if value is not None else None

    def get_technique_status(self, attack_id: str) -> str:
        """Classify an explicit ID without discarding revoked or deprecated evidence."""
        value = self._data.get_object_by_attack_id(attack_id.upper(), "attack-pattern")
        if value is None:
            return "UNKNOWN"
        if bool(_field(value, "revoked", False)):
            return "REVOKED"
        if bool(_field(value, "x_mitre_deprecated", False)):
            return "DEPRECATED"
        return "ACTIVE"

    def get_group(self, identifier: str) -> ActorRecord | None:
        """Return one active group by STIX ID, ATT&CK ID, exact name, or exact alias."""
        normalized = identifier.casefold()
        for group in self.get_groups():
            if normalized in {group.stix_id.casefold(), group.attack_id.casefold(), group.name.casefold()}:
                return group
            if normalized in {alias.casefold() for alias in group.aliases}:
                return group
        return None

    def get_groups(self) -> list[ActorRecord]:
        """Return all active groups from the local bundle."""
        if self._groups_cache is None:
            self._groups_cache = [
                actor
                for group in self._data.get_groups(remove_revoked_deprecated=True)
                if (actor := self._to_actor(group)) is not None
            ]
        return list(self._groups_cache)

    def get_techniques(self) -> list[AttackTechnique]:
        """Return all active techniques from the local bundle."""
        return [
            technique
            for value in self._data.get_techniques(remove_revoked_deprecated=True)
            if (technique := self._to_technique(value)) is not None
        ]

    def get_techniques_for_group(self, group_id: str) -> list[AttackTechnique]:
        """Return active techniques used by an exact local group identifier."""
        group = self.get_group(group_id)
        if group is None:
            return []
        return [
            technique
            for value in self._direct_targets(group.stix_id, "uses", {"attack-pattern"})
            if (technique := self._to_technique(value)) is not None
        ]

    def get_technique_summaries_for_group(self, group_id: str) -> list[AttackTechnique]:
        """Return direct techniques with only the fields required by sector analysis."""
        group = self.get_group(group_id)
        if group is None:
            return []
        return [
            technique
            for value in self._direct_targets(group.stix_id, "uses", {"attack-pattern"})
            if (technique := self._to_technique_summary(value)) is not None
        ]

    def get_groups_for_technique(self, technique_id: str) -> list[ActorRecord]:
        """Return active groups using an exact local technique identifier."""
        technique = self.get_technique(technique_id)
        if technique is None:
            return []
        return [
            actor
            for value in self._direct_sources(technique.stix_id, "uses", {"intrusion-set"})
            if (actor := self._to_actor(value)) is not None
        ]

    def get_mitigations_for_technique_by_stix_id(self, technique_stix_id: str) -> list[MitigationRef]:
        """Return active mitigation records for a technique STIX identifier."""
        return [
            MitigationRef(
                attack_id=_attack_id(value),
                name=str(_field(value, "name", NOT_AVAILABLE)),
                description=str(_field(value, "description", NOT_AVAILABLE)),
            )
            for value in _relationship_objects(self._data.get_mitigations_mitigating_technique(technique_stix_id))
        ]

    def get_mitigations_for_technique(self, technique_id: str) -> list[MitigationRef]:
        """Return active mitigation records for an ATT&CK technique ID."""
        technique = self.get_technique(technique_id)
        return self.get_mitigations_for_technique_by_stix_id(technique.stix_id) if technique else []

    def get_data_components_for_technique_by_stix_id(self, technique_stix_id: str) -> list[DataComponentRef]:
        """Return active data components for a technique STIX identifier."""
        if self.get_capabilities().detection_route == "detection-strategy":
            unique: dict[tuple[str, str], DataComponentRef] = {}
            for evidence in self.get_detection_evidence_by_stix_id(technique_stix_id, NOT_AVAILABLE):
                item = DataComponentRef(
                    name=evidence.data_component_name,
                    data_source_name=evidence.log_source_name
                    if evidence.log_source_name != NOT_AVAILABLE
                    else evidence.channel,
                )
                unique.setdefault((item.name, item.data_source_name), item)
            return list(unique.values())
        return self._legacy_data_components(technique_stix_id)

    def get_detection_evidence_by_stix_id(
        self, technique_stix_id: str, technique_attack_id: str
    ) -> list[DetectionEvidence]:
        """Normalize current strategy/analytic or historical data-component detection data."""
        if self.get_capabilities().detection_route == "detection-strategy":
            results: list[DetectionEvidence] = []
            strategy_entries = self._data.get_detection_strategies_detecting_technique(technique_stix_id)
            for strategy in _relationship_objects(strategy_entries):
                strategy_id = str(_field(strategy, "id", NOT_AVAILABLE))
                for analytic in self._data.get_analytics_by_detection_strategy(
                    strategy_id, remove_revoked_deprecated=True
                ):
                    for log_source in _field(analytic, "x_mitre_log_source_references", []) or []:
                        component_id = str(_field(log_source, "x_mitre_data_component_ref", NOT_AVAILABLE))
                        component = None
                        if component_id != NOT_AVAILABLE:
                            try:
                                component = self._data.get_object_by_stix_id(component_id)
                            except ValueError:
                                component = None
                        results.append(
                            DetectionEvidence(
                                technique_id=technique_attack_id,
                                strategy_id=_attack_id(strategy),
                                strategy_name=str(_field(strategy, "name", NOT_AVAILABLE)),
                                analytic_id=_attack_id(analytic),
                                analytic_name=str(_field(analytic, "name", NOT_AVAILABLE)),
                                analytic_description=str(_field(analytic, "description", NOT_AVAILABLE)),
                                data_component_id=_attack_id(component) if component is not None else NOT_AVAILABLE,
                                data_component_name=str(_field(component, "name", NOT_AVAILABLE)),
                                log_source_name=str(_field(log_source, "name", NOT_AVAILABLE)),
                                channel=str(_field(log_source, "channel", NOT_AVAILABLE)),
                                platforms=tuple(
                                    str(value) for value in (_field(analytic, "x_mitre_platforms", []) or [])
                                ),
                            )
                        )
            return results
        if self.get_capabilities().detection_route == "legacy-data-component":
            return [
                DetectionEvidence(
                    technique_id=technique_attack_id,
                    data_component_name=item.name,
                    log_source_name=item.data_source_name,
                )
                for item in self._legacy_data_components(technique_stix_id)
            ]
        return []

    def _legacy_data_components(self, technique_stix_id: str) -> list[DataComponentRef]:
        components: list[DataComponentRef] = []
        for value in _relationship_objects(self._data.get_datacomponents_detecting_technique(technique_stix_id)):
            data_source_name = NOT_AVAILABLE
            data_source_ref = _field(value, "x_mitre_data_source_ref")
            if isinstance(data_source_ref, str):
                try:
                    data_source_name = str(
                        _field(self._data.get_object_by_stix_id(data_source_ref), "name", NOT_AVAILABLE)
                    )
                except ValueError:
                    pass
            components.append(
                DataComponentRef(name=str(_field(value, "name", NOT_AVAILABLE)), data_source_name=data_source_name)
            )
        return components

    def get_data_components_for_technique(self, technique_id: str) -> list[DataComponentRef]:
        """Return active data components for an ATT&CK technique ID."""
        technique = self.get_technique(technique_id)
        return self.get_data_components_for_technique_by_stix_id(technique.stix_id) if technique else []

    def get_software_for_group(self, group_id: str) -> list[SoftwareRecord]:
        """Return active software used by an exact local group identifier."""
        group = self.get_group(group_id)
        if group is None:
            return []
        return [
            record
            for value in self._direct_targets(group.stix_id, "uses", {"malware", "tool"})
            if (record := self._to_software(value)) is not None
        ]

    def get_software_summaries_for_group(self, group_id: str) -> list[SoftwareRecord]:
        """Return direct software identities without unused reverse relationship enrichment."""
        group = self.get_group(group_id)
        if group is None:
            return []
        return [
            record
            for value in self._direct_targets(group.stix_id, "uses", {"malware", "tool"})
            if (record := self._to_software_summary(value)) is not None
        ]

    def get_campaigns_for_group(self, group_id: str) -> list[CampaignRecord]:
        """Return active campaigns attributed to an exact local group identifier."""
        group = self.get_group(group_id)
        if group is None:
            return []
        return [
            record
            for value in _relationship_objects(self._data.get_campaigns_attributed_to_group(group.stix_id))
            if (record := self._to_campaign(value)) is not None
        ]

    def get_all_tactics(self) -> list[dict[str, str]]:
        """Return active tactics in Enterprise matrix order."""
        tactics_by_matrix = self._data.get_tactics_by_matrix()
        tactics = tactics_by_matrix.get("Enterprise ATT&CK")
        if tactics is None:
            tactics = self._data.get_tactics(remove_revoked_deprecated=True)
        return [
            {
                "stix_id": str(_field(tactic, "id", NOT_AVAILABLE)),
                "attack_id": _attack_id(tactic),
                "name": str(_field(tactic, "name", NOT_AVAILABLE)),
                "shortname": str(_field(tactic, "x_mitre_shortname", NOT_AVAILABLE)),
            }
            for tactic in tactics
            if _active(tactic)
        ]

    def get_version(self) -> str | None:
        """Return the version declared by the installed bundle, if available."""
        version = self._metadata["version"]
        return str(version) if version is not None else None

    def get_bundle_sha256(self) -> str:
        """Return the SHA-256 of the installed bundle."""
        return str(self._metadata["sha256"])

    def get_bundle_path(self) -> str:
        """Return the resolved local path of the installed bundle."""
        return str(self._bundle_path)

    def get_capabilities(self) -> AttackCapabilities:
        """Return the immutable runtime capability profile for this bundle."""
        return cast(AttackCapabilities, self._metadata["capabilities"])
