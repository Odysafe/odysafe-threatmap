"""Application service for the Report to CTI Bundle workflow."""

import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from odysafe_threatmap.domain.models import ActorRecord, AttackTechnique, ExtractionResult, ReportMetadata
from odysafe_threatmap.infrastructure.attack.repository import AttackRepository
from odysafe_threatmap.infrastructure.extraction.iocsearcher_adapter import read_report_text
from odysafe_threatmap.infrastructure.extraction.pipeline import ExtractionPipeline
from odysafe_threatmap.utils.hashing import compute_sha256


class ReportMetadataOptions(BaseModel):
    """Optional user-provided report metadata."""

    name: str | None = None
    source: str | None = None
    published_date: datetime | None = None
    tlp: str | None = None
    confidence: str | None = None


class GroupOverlap(BaseModel):
    """Calculated TTP overlap, explicitly not an attribution."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    actor: ActorRecord
    common_technique_ids: list[str]
    overlap_percent: float


class ReportBundleResult(BaseModel):
    """Structured output of the report bundle service, independent of Excel."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    report_metadata: ReportMetadata
    extraction_result: ExtractionResult
    techniques: list[AttackTechnique]
    detected_actors: list[ActorRecord]
    associated_groups: list[GroupOverlap]
    cti_density: float | None
    attack_version: str | None
    attack_stix_version: str
    attack_bundle_path: str
    attack_bundle_sha256: str
    technique_statuses: dict[str, str] = Field(default_factory=dict)


class ReportBundleService:
    """Build a deterministic CTI bundle from one local text report."""

    def __init__(self, extraction_pipeline: ExtractionPipeline, attack_repo: AttackRepository) -> None:
        self._extraction_pipeline = extraction_pipeline
        self._attack_repo = attack_repo

    def build_bundle(self, file_path: Path, metadata: ReportMetadataOptions) -> ReportBundleResult:
        """Extract, enrich, correlate, and summarize one report without exporting it."""
        path = Path(file_path)
        text = read_report_text(path)
        extraction = self._extraction_pipeline.extract(path)
        report_metadata = ReportMetadata(
            report_id=str(uuid4()),
            name=metadata.name or path.stem,
            source=metadata.source,
            published_date=metadata.published_date,
            tlp=metadata.tlp,
            confidence=metadata.confidence,
            filename=path.name,
            sha256=compute_sha256(path),
            word_count=extraction.word_count,
            line_count=extraction.line_count,
        )
        techniques = [
            technique
            for ttp in extraction.ttps
            if ttp.validated and (technique := self._attack_repo.get_technique(ttp.attack_id)) is not None
        ]
        status_resolver = getattr(self._attack_repo, "get_technique_status", None)
        technique_statuses = {
            ttp.attack_id: (
                status_resolver(ttp.attack_id)
                if callable(status_resolver)
                else ("ACTIVE" if ttp.validated else "UNKNOWN")
            )
            for ttp in extraction.ttps
        }
        detected_actors = self._detect_explicit_actors(text)
        associated_groups = self._calculate_group_overlaps(techniques)
        occurrences = sum(indicator.occurrences for indicator in extraction.indicators) + sum(
            ttp.occurrences for ttp in extraction.ttps
        )
        density = occurrences / report_metadata.word_count * 1000 if report_metadata.word_count else None
        return ReportBundleResult(
            report_metadata=report_metadata,
            extraction_result=extraction,
            techniques=techniques,
            detected_actors=detected_actors,
            associated_groups=associated_groups,
            cti_density=density,
            attack_version=self._attack_repo.get_version(),
            attack_stix_version=self._attack_repo.get_capabilities().stix_version,
            attack_bundle_path=self._attack_repo.get_bundle_path(),
            attack_bundle_sha256=self._attack_repo.get_bundle_sha256(),
            technique_statuses=technique_statuses,
        )

    def _detect_explicit_actors(self, text: str) -> list[ActorRecord]:
        """Detect only exact group IDs, names, and aliases present in the report."""
        detected: list[ActorRecord] = []
        for actor in self._attack_repo.get_groups():
            candidates = (actor.attack_id, actor.stix_id, actor.name, *actor.aliases)
            if any(self._contains_exact(text, candidate) for candidate in candidates if candidate):
                detected.append(actor)
        return detected

    @staticmethod
    def _contains_exact(text: str, candidate: str) -> bool:
        return re.search(rf"(?<!\w){re.escape(candidate)}(?!\w)", text, flags=re.IGNORECASE) is not None

    def _calculate_group_overlaps(self, techniques: list[AttackTechnique]) -> list[GroupOverlap]:
        """Calculate TTP overlap for context without making attribution claims."""
        if not techniques:
            return []
        groups: dict[str, ActorRecord] = {}
        overlaps: defaultdict[str, set[str]] = defaultdict(set)
        for technique in techniques:
            for actor in self._attack_repo.get_groups_for_technique(technique.attack_id):
                groups[actor.stix_id] = actor
                overlaps[actor.stix_id].add(technique.attack_id)
        total = len(techniques)
        return sorted(
            [
                GroupOverlap(
                    actor=groups[stix_id],
                    common_technique_ids=sorted(attack_ids),
                    overlap_percent=len(attack_ids) / total * 100,
                )
                for stix_id, attack_ids in overlaps.items()
            ],
            key=lambda overlap: (-len(overlap.common_technique_ids), overlap.actor.name),
        )
