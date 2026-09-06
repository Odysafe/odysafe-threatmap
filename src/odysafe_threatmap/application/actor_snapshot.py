"""Application service for deterministic ATT&CK actor snapshots."""

from collections.abc import Iterable
from typing import Protocol, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from odysafe_threatmap.domain.exceptions import ActorNotFoundError, AmbiguousActorError
from odysafe_threatmap.domain.models import ActorRecord, AttackTechnique, CampaignRecord, SoftwareRecord
from odysafe_threatmap.infrastructure.attack.repository import AttackRepository


class ActorSnapshotOptions(BaseModel):
    """Options that control the scope of an actor snapshot."""

    include_campaigns: bool = True
    include_local_metadata: bool = False


class ActorSnapshotResult(BaseModel):
    """A complete, exporter-agnostic actor snapshot."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    actors: list[ActorRecord]
    actor_techniques: dict[str, list[AttackTechnique]]
    actor_software: dict[str, list[SoftwareRecord]]
    actor_campaigns: dict[str, list[CampaignRecord]]
    software: list[SoftwareRecord]
    campaigns: list[CampaignRecord]
    technique_popularity: dict[str, int]
    attack_version: str | None
    attack_stix_version: str
    attack_bundle_path: str
    attack_bundle_sha256: str
    options: ActorSnapshotOptions = Field(default_factory=ActorSnapshotOptions)

    @property
    def techniques(self) -> list[AttackTechnique]:
        """Return the unique techniques used by resolved actors."""
        return _unique_records(technique for techniques in self.actor_techniques.values() for technique in techniques)


class _StixRecord(Protocol):
    @property
    def stix_id(self) -> str: ...


RecordT = TypeVar("RecordT", bound=_StixRecord)


def _unique_records(records: Iterable[RecordT]) -> list[RecordT]:
    """Preserve record order while deduplicating domain records by STIX identifier."""
    unique: dict[str, RecordT] = {}
    for record in records:
        unique.setdefault(record.stix_id, record)
    return list(unique.values())


class ActorSnapshotService:
    """Build actor snapshots using only the local ATT&CK repository."""

    def __init__(self, attack_repo: AttackRepository) -> None:
        self._attack_repo = attack_repo

    def build_snapshot(self, actor_identifiers: list[str], options: ActorSnapshotOptions) -> ActorSnapshotResult:
        """Resolve actors and collect structured ATT&CK relationships."""
        if not actor_identifiers:
            raise ActorNotFoundError("At least one actor identifier is required.")

        actors = self._resolve_actors(actor_identifiers)
        actor_techniques = {
            actor.stix_id: self._attack_repo.get_techniques_for_group(actor.stix_id) for actor in actors
        }
        actor_software = {actor.stix_id: self._attack_repo.get_software_for_group(actor.stix_id) for actor in actors}
        actor_campaigns = {
            actor.stix_id: self._attack_repo.get_campaigns_for_group(actor.stix_id) if options.include_campaigns else []
            for actor in actors
        }
        techniques = [technique for values in actor_techniques.values() for technique in values]
        software = _unique_records(record for values in actor_software.values() for record in values)
        campaigns = _unique_records(record for values in actor_campaigns.values() for record in values)

        return ActorSnapshotResult(
            actors=actors,
            actor_techniques=actor_techniques,
            actor_software=actor_software,
            actor_campaigns=actor_campaigns,
            software=software,
            campaigns=campaigns,
            technique_popularity={technique.stix_id: technique.groups_count for technique in techniques},
            attack_version=self._attack_repo.get_version(),
            attack_stix_version=self._attack_repo.get_capabilities().stix_version,
            attack_bundle_path=self._attack_repo.get_bundle_path(),
            attack_bundle_sha256=self._attack_repo.get_bundle_sha256(),
            options=options,
        )

    def _resolve_actors(self, identifiers: Iterable[str]) -> list[ActorRecord]:
        resolved: dict[str, ActorRecord] = {}
        groups = self._attack_repo.get_groups()
        for identifier in identifiers:
            actor = self._resolve_actor(identifier, groups)
            resolved.setdefault(actor.stix_id, actor)
        return list(resolved.values())

    @staticmethod
    def _resolve_actor(identifier: str, groups: list[ActorRecord]) -> ActorRecord:
        value = identifier.strip()
        if not value:
            raise ActorNotFoundError("Actor identifier cannot be empty.")
        normalized = value.casefold()
        for selector in (
            lambda actor: actor.stix_id == value,
            lambda actor: actor.attack_id == value.upper(),
            lambda actor: actor.name.casefold() == normalized,
            lambda actor: normalized in {alias.casefold() for alias in actor.aliases},
        ):
            candidates = [actor for actor in groups if selector(actor)]
            if len(candidates) == 1:
                return candidates[0]
            if len(candidates) > 1:
                names = ", ".join(actor.name for actor in candidates)
                raise AmbiguousActorError(f"Ambiguous actor identifier '{value}': {names}.")
        raise ActorNotFoundError(f"Actor not found: {value}.")
