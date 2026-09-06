"""Fail-closed offline policy boundary for txt2stix integration."""

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from odysafe_threatmap.domain.exceptions import OfflinePolicyViolation
from odysafe_threatmap.domain.models import ExtractionResult

SUPPORTED_LOCAL_PATTERN_CATEGORIES = frozenset({"pattern_ioc", "pattern_attack", "pattern_cve"})


class Txt2stixOfflineConfig(BaseModel):
    """Strict configuration for the only permitted txt2stix execution mode."""

    model_config = ConfigDict(frozen=True)

    relationship_mode: Literal["standard"]
    no_remote: Literal[True]
    allowed_patterns: tuple[str, ...] = Field(default_factory=tuple)
    local_lookup_files: dict[str, Path] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_policy(self) -> "Txt2stixOfflineConfig":
        """Reject AI, remote, unknown, and non-local extraction settings."""
        for slug in self.allowed_patterns:
            if slug.startswith("ai_") or slug not in SUPPORTED_LOCAL_PATTERN_CATEGORIES:
                raise OfflinePolicyViolation(f"Forbidden txt2stix extractor: {slug}")
        for slug, path in self.local_lookup_files.items():
            if not slug.startswith("lookup_") or not path.is_file():
                raise OfflinePolicyViolation(f"Lookup must reference a controlled local file: {slug}")
        return self


def load_offline_config(config_path: Path) -> Txt2stixOfflineConfig:
    """Load and validate a txt2stix offline policy before any extraction call."""
    try:
        raw_config = yaml.safe_load(Path(config_path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as error:
        raise OfflinePolicyViolation(f"Unable to load offline extraction policy: {error}") from error
    if not isinstance(raw_config, dict):
        raise OfflinePolicyViolation("Offline extraction policy must be a YAML mapping.")
    return Txt2stixOfflineConfig.model_validate(raw_config)


class Txt2stixAdapter:
    """Policy-enforcing facade that intentionally has no txt2stix runtime import.

    txt2stix 1.7.1 imports aggregate modules that include LLM and remote paths.
    Until a pattern-only runner is independently audited, this adapter returns no
    supplemental results rather than risking a prohibited execution path.
    """

    def __init__(self, config: Txt2stixOfflineConfig) -> None:
        self._config = config

    def assert_slug_allowed(self, slug: str) -> None:
        """Raise when a requested extractor slug is not explicitly authorized."""
        if slug in self._config.allowed_patterns or slug in self._config.local_lookup_files:
            return
        raise OfflinePolicyViolation(f"txt2stix extractor is not allowlisted: {slug}")

    def extract(self, file_path: Path) -> ExtractionResult:
        """Return no supplemental data while preserving the fail-closed policy.

        The path is validated so callers receive deterministic input errors from
        the canonical adapter before any future runner integration is attempted.
        """
        if not Path(file_path).is_file():
            raise OfflinePolicyViolation(f"Input report does not exist: {file_path}")
        return ExtractionResult()
