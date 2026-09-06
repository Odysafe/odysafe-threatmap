"""Domain models shared by local ATT&CK and extraction layers."""

from dataclasses import dataclass, field
from datetime import datetime

NOT_AVAILABLE = "N/A"


@dataclass(frozen=True, slots=True)
class MitigationRef:
    """A mitigation related to an ATT&CK technique."""

    attack_id: str
    name: str
    description: str = NOT_AVAILABLE


@dataclass(frozen=True, slots=True)
class DataComponentRef:
    """A data component that can detect an ATT&CK technique."""

    name: str
    data_source_name: str = NOT_AVAILABLE


@dataclass(frozen=True, slots=True)
class DetectionEvidence:
    """Normalized ATT&CK detection evidence independent of bundle representation."""

    technique_id: str
    strategy_id: str = NOT_AVAILABLE
    strategy_name: str = NOT_AVAILABLE
    analytic_id: str = NOT_AVAILABLE
    analytic_name: str = NOT_AVAILABLE
    analytic_description: str = NOT_AVAILABLE
    data_component_id: str = NOT_AVAILABLE
    data_component_name: str = NOT_AVAILABLE
    log_source_name: str = NOT_AVAILABLE
    channel: str = NOT_AVAILABLE
    platforms: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AttackTechnique:
    """A normalized ATT&CK technique record."""

    attack_id: str
    stix_id: str
    name: str
    tactics: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    description: str = NOT_AVAILABLE
    is_subtechnique: bool = False
    mitigations: tuple[MitigationRef, ...] = ()
    data_components: tuple[DataComponentRef, ...] = ()
    detection_evidence: tuple[DetectionEvidence, ...] = ()
    groups_count: int = 0
    software_count: int = 0
    attack_url: str = NOT_AVAILABLE


@dataclass(frozen=True, slots=True)
class ActorRecord:
    """A normalized ATT&CK intrusion-set record."""

    attack_id: str
    stix_id: str
    name: str
    aliases: tuple[str, ...] = ()
    description: str = NOT_AVAILABLE
    first_seen: str = NOT_AVAILABLE
    last_seen: str = NOT_AVAILABLE
    resource_level: str = NOT_AVAILABLE
    primary_motivation: str = NOT_AVAILABLE
    secondary_motivations: tuple[str, ...] = ()
    sectors: tuple[str, ...] = ()
    regions: tuple[str, ...] = ()
    origin: str = NOT_AVAILABLE
    attack_url: str = NOT_AVAILABLE


@dataclass(frozen=True, slots=True)
class SoftwareRecord:
    """A normalized ATT&CK software, malware, or tool record."""

    attack_id: str
    stix_id: str
    name: str
    type: str
    platforms: tuple[str, ...] = ()
    description: str = NOT_AVAILABLE
    techniques: tuple[str, ...] = ()
    other_groups: tuple[str, ...] = ()
    attack_url: str = NOT_AVAILABLE


@dataclass(frozen=True, slots=True)
class CampaignRecord:
    """A normalized ATT&CK campaign record."""

    attack_id: str
    stix_id: str
    name: str
    first_seen: str | None = None
    last_seen: str | None = None
    description: str = NOT_AVAILABLE
    techniques: tuple[str, ...] = ()
    software: tuple[str, ...] = ()
    attack_url: str = NOT_AVAILABLE


@dataclass(frozen=True, slots=True)
class SectorRecord:
    """A sector derived exclusively from a local metadata mapping."""

    name: str
    groups_count: int
    techniques_count: int
    mapping_source: str
    mapping_version: str


@dataclass(frozen=True, slots=True)
class AttackTechniqueWithSectorData:
    """An ATT&CK technique with explicit sector-mapping frequency data."""

    technique: AttackTechnique
    sector_groups_count: int
    sector_groups_percent: float
    sector_groups: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PriorityRecord:
    """A configurable local Odysafe priority, not an ATT&CK score."""

    technique_id: str
    technique_name: str
    tactic: str
    frequency_score: int
    tactic_impact_score: int
    priority_score: int
    priority_label: str


@dataclass(frozen=True, slots=True)
class AttackTechniqueWithFrequency:
    """An ATT&CK technique associated with a normalized numeric frequency."""

    technique: AttackTechnique
    frequency: int


@dataclass(frozen=True, slots=True)
class AttackTechniqueWithRisk:
    """An ATT&CK technique associated with an Odysafe-local risk score."""

    technique: AttackTechnique
    priority_score: int
    priority_label: str


@dataclass(frozen=True, slots=True)
class ExtractedIndicatorWithCorroboration:
    """An extracted indicator with explicit cross-report corroboration data."""

    indicator: "ExtractedIndicator"
    reports: tuple[str, ...]
    primary_sources_count: int
    corroboration_status: str


@dataclass(frozen=True, slots=True)
class AttackTechniqueWithCorroboration:
    """An ATT&CK technique with explicit cross-report corroboration data."""

    technique: AttackTechnique
    reports: tuple[str, ...]
    primary_sources: tuple[str, ...]
    corroboration_status: str


@dataclass(frozen=True, slots=True)
class SigmaRuleRecord:
    """A parsed Sigma rule with normalized ATT&CK tags only."""

    path: str
    rule_id: str | None
    title: str
    status: str
    level: str
    attack_tags: tuple[str, ...] = ()
    parse_errors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CoverageRecord:
    """Strict tag-based Sigma coverage for one ATT&CK technique."""

    technique: AttackTechnique
    occurrences: int
    exact_rules: tuple[str, ...]
    hierarchical_rules: tuple[str, ...]
    status: str
    priority: str
    priority_score: int


@dataclass(slots=True)
class ExtractedIndicator:
    """A deduplicated observable extracted from a report."""

    type: str
    normalized_value: str
    raw_value: str
    defanged: bool
    occurrences: int
    first_offset: int
    first_line: int
    lines: list[int] = field(default_factory=list)
    extraction_engine: str = "iocsearcher"


@dataclass(slots=True)
class ExtractedTTP:
    """An explicit ATT&CK technique identifier extracted from a report."""

    attack_id: str
    occurrences: int
    offsets: list[int] = field(default_factory=list)
    lines: list[int] = field(default_factory=list)
    validated: bool = False
    extraction_engine: str = "iocsearcher"


@dataclass(frozen=True, slots=True)
class ReportMetadata:
    """Traceability metadata computed from a text report."""

    report_id: str
    name: str
    source: str | None
    published_date: datetime | None
    tlp: str | None
    confidence: str | None
    filename: str
    sha256: str
    word_count: int
    line_count: int


@dataclass(slots=True)
class ExtractionResult:
    """Structured, deterministic extraction output for one text report."""

    indicators: list[ExtractedIndicator] = field(default_factory=list)
    ttps: list[ExtractedTTP] = field(default_factory=list)
    word_count: int = 0
    line_count: int = 0
