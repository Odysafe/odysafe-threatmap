"""Application service for local sector threat profiles."""

from collections import defaultdict
from dataclasses import replace

from pydantic import BaseModel, ConfigDict, Field

from odysafe_threatmap.config.schemas import ActorMetadataConfig, ActorMetadataEntry
from odysafe_threatmap.config.sectors import SectorRegistry
from odysafe_threatmap.domain.models import (
    ActorRecord,
    AttackTechnique,
    AttackTechniqueWithSectorData,
    PriorityRecord,
    SectorRecord,
    SoftwareRecord,
)
from odysafe_threatmap.domain.scoring import calculate_priority_score
from odysafe_threatmap.infrastructure.attack.repository import AttackRepository


class SectorProfileOptions(BaseModel):
    """Options controlling local sector profile presentation."""

    include_regions: bool = False
    tactic_weights: dict[str, int] = Field(default_factory=dict)
    priority_thresholds: dict[str, int] = Field(default_factory=dict)


class SectorProfileResult(BaseModel):
    """Exporter-agnostic profile generated from an explicit local mapping."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    sectors: list[SectorRecord]
    actors: list[ActorRecord]
    actor_techniques: dict[str, list[AttackTechnique]]
    actor_software: dict[str, list[SoftwareRecord]]
    techniques: list[AttackTechniqueWithSectorData]
    risk_matrix: list[PriorityRecord]
    regions_data: dict[str, list[ActorRecord]]
    warnings: list[str]
    attack_version: str | None
    attack_stix_version: str
    attack_bundle_path: str
    attack_bundle_sha256: str


class SectorProfileService:
    """Build profiles using ATT&CK relationships and explicit local curation only."""

    def __init__(
        self,
        attack_repo: AttackRepository,
        actor_metadata: ActorMetadataConfig,
        sector_registry: SectorRegistry | None = None,
    ) -> None:
        self._attack_repo = attack_repo
        self._metadata = actor_metadata
        self._sector_registry = sector_registry or SectorRegistry.load()

    def build_profile(self, sector_names: list[str], options: SectorProfileOptions) -> SectorProfileResult:
        """Build a deterministic profile for requested exact local sector names."""
        requested = self._resolve_sectors(sector_names)
        entries = [entry for entry in self._metadata.groups if any(s in requested for s in entry.sectors)]
        warnings: list[str] = []
        actors: list[ActorRecord] = []
        actor_entries: dict[str, ActorMetadataEntry] = {}
        for entry in entries:
            actor = self._attack_repo.get_group(entry.attack_id)
            if actor is None:
                warnings.append(f"Mapped ATT&CK group is not in the local bundle: {entry.attack_id}.")
                continue
            actor = replace(
                actor,
                sectors=tuple(entry.sectors),
                regions=tuple(entry.regions),
                origin=entry.origin or "N/A",
            )
            actor_entries[actor.stix_id] = entry
            if actor.stix_id not in {item.stix_id for item in actors}:
                actors.append(actor)
        actor_techniques = {
            actor.stix_id: self._attack_repo.get_technique_summaries_for_group(actor.stix_id) for actor in actors
        }
        actor_software = {
            actor.stix_id: self._attack_repo.get_software_summaries_for_group(actor.stix_id) for actor in actors
        }
        techniques = self._techniques(actor_techniques, actors)
        weights = options.tactic_weights or {"Initial Access": 4}
        thresholds = options.priority_thresholds or {
            "critical_threshold": 150,
            "high_threshold": 100,
            "moderate_threshold": 50,
        }
        risks = sorted(
            (calculate_priority_score(item, weights, thresholds) for item in techniques),
            key=lambda item: item.priority_score,
            reverse=True,
        )
        sector_records = self._sectors(requested, actors, actor_techniques, actor_entries)
        regions = self._regions(actors) if options.include_regions else {}
        return SectorProfileResult(
            sectors=sector_records,
            actors=actors,
            actor_techniques=actor_techniques,
            actor_software=actor_software,
            techniques=techniques,
            risk_matrix=risks,
            regions_data=regions,
            warnings=warnings,
            attack_version=self._attack_repo.get_version(),
            attack_stix_version=self._attack_repo.get_capabilities().stix_version,
            attack_bundle_path=self._attack_repo.get_bundle_path(),
            attack_bundle_sha256=self._attack_repo.get_bundle_sha256(),
        )

    def _resolve_sectors(self, names: list[str]) -> list[str]:
        return self._sector_registry.resolve_many(names)

    @staticmethod
    def _techniques(
        actor_techniques: dict[str, list[AttackTechnique]], actors: list[ActorRecord]
    ) -> list[AttackTechniqueWithSectorData]:
        grouped: dict[str, tuple[AttackTechnique, list[str]]] = {}
        for actor in actors:
            for technique in actor_techniques[actor.stix_id]:
                grouped.setdefault(technique.stix_id, (technique, []))[1].append(actor.name)
        total = len(actors)
        return (
            [
                AttackTechniqueWithSectorData(
                    technique=item[0],
                    sector_groups_count=len(set(item[1])),
                    sector_groups_percent=100 * len(set(item[1])) / total,
                    sector_groups=tuple(sorted(set(item[1]))),
                )
                for item in grouped.values()
            ]
            if total
            else []
        )

    def _sectors(
        self,
        requested: list[str],
        actors: list[ActorRecord],
        actor_techniques: dict[str, list[AttackTechnique]],
        actor_entries: dict[str, ActorMetadataEntry],
    ) -> list[SectorRecord]:
        result = []
        for sector in requested:
            selected = [actor for actor in actors if sector in actor_entries[actor.stix_id].sectors]
            ids = {item.stix_id for actor in selected for item in actor_techniques[actor.stix_id]}
            result.append(SectorRecord(sector, len(selected), len(ids), "internal-curation", self._metadata.version))
        return result

    @staticmethod
    def _regions(actors: list[ActorRecord]) -> dict[str, list[ActorRecord]]:
        regions: dict[str, list[ActorRecord]] = defaultdict(list)
        for actor in actors:
            for region in actor.regions:
                regions[region].append(actor)
        return dict(regions)
