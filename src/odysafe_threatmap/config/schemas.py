"""Pydantic schemas for application configuration."""

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class ApplicationConfig(BaseModel):
    """Base configuration with support for future feature-specific keys."""

    model_config = ConfigDict(extra="allow")

    attack_bundle_path: Path | None = None


class ActorMetadataEntry(BaseModel):
    """One manually curated actor metadata entry."""

    attack_id: str
    sectors: list[str] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)
    origin: str | None = None
    source: str = "internal-curation"
    comment: str | None = None


class ActorMetadataConfig(BaseModel):
    """Versioned local sector and region mappings for ATT&CK groups."""

    version: str
    groups: list[ActorMetadataEntry] = Field(default_factory=list)


class TacticImpactConfig(BaseModel):
    """Local tactic impact weights used by the Odysafe heuristic."""

    tactics: dict[str, dict[str, int | str]]


class PriorityThresholds(BaseModel):
    """Thresholds used to label local Odysafe priority scores."""

    critical_threshold: int
    high_threshold: int
    moderate_threshold: int
    low_threshold: int = 0


class SectorDefinition(BaseModel):
    """One user-facing industry backed by explicit local mappings."""

    id: str
    order: int
    name: str
    icon: str = "•"
    description: str
    aliases: list[str] = Field(default_factory=list)
    mitre: dict[str, list[str]] = Field(default_factory=dict)
    keywords: list[str] = Field(default_factory=list)
