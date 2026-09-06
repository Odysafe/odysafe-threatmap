"""Offline orchestration and deterministic merging of extraction adapters."""

from pathlib import Path

from odysafe_threatmap.domain.models import ExtractedIndicator, ExtractedTTP, ExtractionResult
from odysafe_threatmap.infrastructure.attack.repository import AttackRepository
from odysafe_threatmap.infrastructure.extraction.exact_lookup import normalize_ttp_id, validate_ttp_id
from odysafe_threatmap.infrastructure.extraction.iocsearcher_adapter import IocsearcherAdapter
from odysafe_threatmap.infrastructure.extraction.txt2stix_adapter import Txt2stixAdapter


class ExtractionPipeline:
    """Merge deterministic extraction results while keeping canonical provenance."""

    def __init__(
        self,
        iocsearcher: IocsearcherAdapter,
        txt2stix: Txt2stixAdapter | None,
        attack_repo: AttackRepository,
    ) -> None:
        self._iocsearcher = iocsearcher
        self._txt2stix = txt2stix
        self._attack_repo = attack_repo

    def extract(self, file_path: Path) -> ExtractionResult:
        """Extract, merge, and locally validate indicators and explicit TTP IDs."""
        canonical = self._iocsearcher.extract(file_path)
        supplemental = self._txt2stix.extract(file_path) if self._txt2stix else ExtractionResult()
        indicators = self._merge_indicators(canonical.indicators, supplemental.indicators)
        ttps = self._merge_ttps(canonical.ttps, supplemental.ttps)
        for ttp in ttps:
            ttp.validated = validate_ttp_id(ttp.attack_id, self._attack_repo)
        return ExtractionResult(
            indicators=indicators,
            ttps=ttps,
            word_count=canonical.word_count,
            line_count=canonical.line_count,
        )

    @staticmethod
    def _merge_indicators(
        canonical: list[ExtractedIndicator], supplemental: list[ExtractedIndicator]
    ) -> list[ExtractedIndicator]:
        merged: dict[tuple[str, str], ExtractedIndicator] = {}
        for indicator in [*canonical, *supplemental]:
            key = (indicator.type, indicator.normalized_value)
            if key not in merged:
                merged[key] = ExtractedIndicator(
                    type=indicator.type,
                    normalized_value=indicator.normalized_value,
                    raw_value=indicator.raw_value,
                    defanged=indicator.defanged,
                    occurrences=indicator.occurrences,
                    first_offset=indicator.first_offset,
                    first_line=indicator.first_line,
                    lines=list(indicator.lines),
                    extraction_engine=indicator.extraction_engine,
                )
                continue
            existing = merged[key]
            existing.occurrences += indicator.occurrences
            existing.defanged = existing.defanged or indicator.defanged
            existing.lines = sorted(set(existing.lines).union(indicator.lines))
            if indicator.first_offset < existing.first_offset:
                existing.raw_value = indicator.raw_value
                existing.first_offset = indicator.first_offset
                existing.first_line = indicator.first_line
            existing.extraction_engine = ExtractionPipeline._merge_engines(
                existing.extraction_engine, indicator.extraction_engine
            )
        return sorted(merged.values(), key=lambda indicator: indicator.first_offset)

    @staticmethod
    def _merge_ttps(canonical: list[ExtractedTTP], supplemental: list[ExtractedTTP]) -> list[ExtractedTTP]:
        merged: dict[str, ExtractedTTP] = {}
        for ttp in [*canonical, *supplemental]:
            attack_id = normalize_ttp_id(ttp.attack_id)
            if attack_id not in merged:
                merged[attack_id] = ExtractedTTP(
                    attack_id=attack_id,
                    occurrences=ttp.occurrences,
                    offsets=list(ttp.offsets),
                    lines=list(ttp.lines),
                    extraction_engine=ttp.extraction_engine,
                )
                continue
            existing = merged[attack_id]
            existing.occurrences += ttp.occurrences
            existing.offsets = sorted(set(existing.offsets).union(ttp.offsets))
            existing.lines = sorted(set(existing.lines).union(ttp.lines))
            existing.extraction_engine = ExtractionPipeline._merge_engines(
                existing.extraction_engine, ttp.extraction_engine
            )
        return sorted(merged.values(), key=lambda ttp: ttp.offsets[0] if ttp.offsets else -1)

    @staticmethod
    def _merge_engines(first: str, second: str) -> str:
        engines = sorted(set(first.split("+", 1) + second.split("+", 1)))
        return "+".join(engines)
