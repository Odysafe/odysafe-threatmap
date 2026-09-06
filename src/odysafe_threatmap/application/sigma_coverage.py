"""Application service for strict Sigma coverage analysis."""

from pathlib import Path

from pydantic import BaseModel, ConfigDict

from odysafe_threatmap.domain.models import CoverageRecord, SigmaRuleRecord
from odysafe_threatmap.infrastructure.attack.repository import AttackRepository
from odysafe_threatmap.infrastructure.extraction.pipeline import ExtractionPipeline
from odysafe_threatmap.infrastructure.sigma.coverage_engine import SigmaCoverageEngine
from odysafe_threatmap.infrastructure.sigma.parser import parse_sigma_rules
from odysafe_threatmap.utils.hashing import compute_sha256


class SigmaCoverageOptions(BaseModel):
    """Options controlling strict parsing and optional rule export."""

    include_rules: bool = False
    strict: bool = False


class SigmaCoverageResult(BaseModel):
    """Exporter-agnostic strict Sigma coverage results."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    coverage: list[CoverageRecord]
    sigma_rules: list[SigmaRuleRecord]
    exact_count: int
    partial_count: int
    none_count: int
    attack_version: str | None
    attack_stix_version: str
    attack_bundle_path: str
    attack_bundle_sha256: str
    include_rules: bool
    input_hashes: dict[str, str]


class SigmaCoverageService:
    """Analyze a report's explicit ATT&CK IDs against local Sigma rule tags."""

    def __init__(
        self, extraction_pipeline: ExtractionPipeline, attack_repo: AttackRepository, tactic_weights: dict[str, int]
    ) -> None:
        self._pipeline = extraction_pipeline
        self._repo = attack_repo
        self._weights = tactic_weights

    def analyze_coverage(
        self, report_path: Path, sigma_source: Path | list[Path], options: SigmaCoverageOptions
    ) -> SigmaCoverageResult:
        """Extract report TTPs and apply only strict ATT&CK Sigma tag matching."""
        extraction = self._pipeline.extract(report_path)
        rules = parse_sigma_rules(sigma_source)
        if options.strict and any(rule.parse_errors for rule in rules):
            raise ValueError("Malformed Sigma rule encountered in strict mode.")
        techniques = [
            technique
            for item in extraction.ttps
            if item.validated
            if (technique := self._repo.get_technique(item.attack_id))
        ]
        coverage = SigmaCoverageEngine(rules, self._weights).analyze_coverage(techniques, extraction.ttps)
        return SigmaCoverageResult(
            coverage=coverage,
            sigma_rules=rules,
            exact_count=sum(item.status == "exact" for item in coverage),
            partial_count=sum(item.status == "partial" for item in coverage),
            none_count=sum(item.status == "none" for item in coverage),
            attack_version=self._repo.get_version(),
            attack_stix_version=self._repo.get_capabilities().stix_version,
            attack_bundle_path=self._repo.get_bundle_path(),
            attack_bundle_sha256=self._repo.get_bundle_sha256(),
            include_rules=options.include_rules,
            input_hashes={
                str(report_path): compute_sha256(report_path),
                **{rule.path: compute_sha256(Path(rule.path)) for rule in rules},
            },
        )
