"""Deterministic Odysafe-local priority scoring."""

from pydantic import BaseModel

from odysafe_threatmap.domain.models import AttackTechniqueWithSectorData, PriorityRecord
from odysafe_threatmap.utils.source_mapping import SourceMapping


class CorroborationRecord(BaseModel):
    """A deterministic corroboration assessment based on explicit source mappings."""

    item_id: str
    item_type: str
    reports_count: int
    reports_with_source: int
    primary_sources_count: int
    corroboration_status: str


class CtiDensityInterpretation(BaseModel):
    """Plain-language interpretation of a calculated CTI observation density."""

    label: str
    explanation: str


def interpret_cti_density(density: float | None) -> CtiDensityInterpretation:
    """Describe technical-observation concentration without implying risk or quality."""
    if density is None:
        return CtiDensityInterpretation(
            label="Not available",
            explanation="The report contains no countable words, so CTI observation density cannot be calculated.",
        )
    rounded = round(density, 1)
    if density == 0:
        label = "No detected observations"
        concentration = "No explicit IOC or TTP occurrences were detected in the report."
    elif density < 10:
        label = "Low concentration"
        concentration = "Explicit CTI observations are sparse relative to the report length."
    elif density < 50:
        label = "Moderate concentration"
        concentration = "Explicit CTI observations appear regularly relative to the report length."
    elif density < 100:
        label = "High concentration"
        concentration = "Explicit CTI observations are concentrated relative to the report length."
    else:
        label = "Very high concentration"
        concentration = "The report is highly concentrated in explicit CTI observations relative to its length."
    return CtiDensityInterpretation(
        label=label,
        explanation=(
            f"Approximately {rounded:.1f} explicit CTI observations were detected per 1,000 words. "
            f"{concentration} This is a concentration indicator only—not a danger, confidence, criticality, "
            "attack-probability, or report-quality score."
        ),
    )


def calculate_priority_score(
    technique: AttackTechniqueWithSectorData,
    tactic_weights: dict[str, int],
    thresholds: dict[str, int],
) -> PriorityRecord:
    """Calculate a configurable local priority from frequency and tactic impact."""
    tactic = technique.technique.tactics[0] if technique.technique.tactics else "N/A"
    frequency_score = round(technique.sector_groups_percent)
    impact_score = tactic_weights.get(tactic, 1) * 20
    priority_score = frequency_score + impact_score
    if priority_score >= thresholds["critical_threshold"]:
        label = "🔴 Critical"
    elif priority_score >= thresholds["high_threshold"]:
        label = "🟠 High"
    elif priority_score >= thresholds["moderate_threshold"]:
        label = "🟡 Moderate"
    else:
        label = "🟢 Low"
    return PriorityRecord(
        technique_id=technique.technique.attack_id,
        technique_name=technique.technique.name,
        tactic=tactic,
        frequency_score=frequency_score,
        tactic_impact_score=impact_score,
        priority_score=priority_score,
        priority_label=label,
    )


def calculate_corroboration(
    item_id: str, item_type: str, reports: list[str], source_mapping: dict[str, SourceMapping]
) -> CorroborationRecord:
    """Assess corroboration solely from complete, explicit primary-source mappings."""
    mapped = [source_mapping[report] for report in reports if report in source_mapping]
    sources = {item.primary_source_id for item in mapped if item.primary_source_id}
    if len(reports) >= 2 and len(mapped) == len(reports) and len(sources) == 1:
        status = "false"
    elif len(sources) >= 2:
        status = "multi-source"
    else:
        status = "undetermined"
    return CorroborationRecord(
        item_id=item_id,
        item_type=item_type,
        reports_count=len(reports),
        reports_with_source=len(mapped),
        primary_sources_count=len(sources),
        corroboration_status=status,
    )
