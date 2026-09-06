"""Application service for deterministic multi-report aggregation."""

from collections import defaultdict
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from odysafe_threatmap.domain.models import (
    AttackTechniqueWithCorroboration,
    ExtractedIndicator,
    ExtractedIndicatorWithCorroboration,
    ExtractionResult,
)
from odysafe_threatmap.domain.scoring import CorroborationRecord, calculate_corroboration
from odysafe_threatmap.infrastructure.attack.repository import AttackRepository
from odysafe_threatmap.infrastructure.extraction.iocsearcher_adapter import SUPPORTED_REPORT_SUFFIXES
from odysafe_threatmap.infrastructure.extraction.pipeline import ExtractionPipeline
from odysafe_threatmap.utils.hashing import compute_sha256
from odysafe_threatmap.utils.source_mapping import SourceMapping, load_source_mapping


class AggregateOptions(BaseModel):
    """Options for selecting reports and an optional explicit source mapping."""

    recursive: bool = False
    source_mapping_path: Path | None = None


class AggregatedReport(BaseModel):
    """Traceability and extraction summary for one unique report."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    filename: str
    path: Path
    sha256: str
    extraction: ExtractionResult
    source_name: str | None = None
    primary_source_id: str | None = None
    warning: str | None = None


class AggregateResult(BaseModel):
    """Exporter-agnostic aggregation of multiple local reports."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    reports: list[AggregatedReport]
    duplicate_paths: list[Path]
    duplicate_of: dict[str, str] = Field(default_factory=dict)
    indicators: list[ExtractedIndicatorWithCorroboration]
    techniques: list[AttackTechniqueWithCorroboration]
    corroboration: list[CorroborationRecord]
    warnings: list[str] = Field(default_factory=list)
    attack_version: str | None
    attack_stix_version: str
    attack_bundle_path: str
    attack_bundle_sha256: str


class MultiReportService:
    """Aggregate existing extraction results without duplicating their pipeline."""

    def __init__(self, extraction_pipeline: ExtractionPipeline, attack_repo: AttackRepository) -> None:
        self._pipeline = extraction_pipeline
        self._attack_repo = attack_repo

    def aggregate_reports(self, report_paths: list[Path], options: AggregateOptions) -> AggregateResult:
        """Extract unique reports, enrich each ATT&CK technique once, and assess corroboration."""
        paths = self._collect_paths(report_paths, options.recursive)
        if not paths:
            raise ValueError("No supported local reports were found (.txt, .html, .htm, .pdf, or .docx).")
        mapping, warnings = self._mapping(options.source_mapping_path)
        reports: list[AggregatedReport] = []
        duplicates: list[Path] = []
        hashes: dict[str, str] = {}
        duplicate_of: dict[str, str] = {}
        for path in paths:
            digest = compute_sha256(path)
            if digest in hashes:
                duplicates.append(path)
                duplicate_of[str(path)] = hashes[digest]
                continue
            hashes[digest] = path.name
            extraction = self._pipeline.extract(path)
            source = mapping.get(path.name)
            reports.append(
                AggregatedReport(
                    filename=path.name,
                    path=path,
                    sha256=digest,
                    extraction=extraction,
                    source_name=source.source_name if source else None,
                    primary_source_id=source.primary_source_id if source else None,
                )
            )
        indicators, indicator_records = self._indicators(reports, mapping)
        techniques, technique_records = self._techniques(reports, mapping)
        return AggregateResult(
            reports=reports,
            duplicate_paths=duplicates,
            duplicate_of=duplicate_of,
            indicators=indicators,
            techniques=techniques,
            corroboration=indicator_records + technique_records,
            warnings=warnings,
            attack_version=self._attack_repo.get_version(),
            attack_stix_version=self._attack_repo.get_capabilities().stix_version,
            attack_bundle_path=self._attack_repo.get_bundle_path(),
            attack_bundle_sha256=self._attack_repo.get_bundle_sha256(),
        )

    @staticmethod
    def _collect_paths(paths: list[Path], recursive: bool) -> list[Path]:
        collected: list[Path] = []
        for path in paths:
            if path.is_dir():
                iterator = path.rglob("*") if recursive else path.glob("*")
                collected.extend(
                    sorted(
                        item
                        for item in iterator
                        if item.is_file() and item.suffix.casefold() in SUPPORTED_REPORT_SUFFIXES
                    )
                )
            elif path.is_file() and path.suffix.casefold() in SUPPORTED_REPORT_SUFFIXES:
                collected.append(path)
        return collected

    @staticmethod
    def _mapping(path: Path | None) -> tuple[dict[str, SourceMapping], list[str]]:
        if path is None:
            return {}, []
        try:
            return load_source_mapping(path), []
        except (OSError, ValueError) as error:
            return {}, [f"Source mapping was ignored: {error}"]

    def _indicators(
        self, reports: list[AggregatedReport], mapping: dict[str, SourceMapping]
    ) -> tuple[list[ExtractedIndicatorWithCorroboration], list[CorroborationRecord]]:
        grouped: dict[tuple[str, str], list[tuple[str, ExtractedIndicator]]] = defaultdict(list)
        for report in reports:
            for indicator in report.extraction.indicators:
                grouped[(indicator.type, indicator.normalized_value)].append((report.filename, indicator))
        results = []
        records = []
        for (_kind, value), entries in grouped.items():
            names = [entry[0] for entry in entries]
            record = calculate_corroboration(value, "ioc", names, mapping)
            records.append(record)
            first = entries[0][1]
            merged = ExtractedIndicator(
                first.type,
                first.normalized_value,
                first.raw_value,
                first.defanged,
                sum(item.occurrences for _, item in entries),
                first.first_offset,
                first.first_line,
                first.lines,
                first.extraction_engine,
            )
            results.append(
                ExtractedIndicatorWithCorroboration(
                    merged, tuple(names), record.primary_sources_count, record.corroboration_status
                )
            )
        return results, records

    def _techniques(
        self, reports: list[AggregatedReport], mapping: dict[str, SourceMapping]
    ) -> tuple[list[AttackTechniqueWithCorroboration], list[CorroborationRecord]]:
        grouped: dict[str, list[str]] = defaultdict(list)
        for report in reports:
            for ttp in report.extraction.ttps:
                if ttp.validated:
                    grouped[ttp.attack_id].append(report.filename)
        results = []
        records = []
        for attack_id, names in grouped.items():
            technique = self._attack_repo.get_technique(attack_id)
            if technique is None:
                continue
            record = calculate_corroboration(attack_id, "ttp", names, mapping)
            records.append(record)
            sources = tuple(sorted({mapping[name].primary_source_id for name in names if name in mapping}))
            results.append(
                AttackTechniqueWithCorroboration(technique, tuple(names), sources, record.corroboration_status)
            )
        return results, records
