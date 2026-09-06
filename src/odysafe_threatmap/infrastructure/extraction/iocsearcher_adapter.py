"""Adapter for deterministic IOC and explicit ATT&CK ID extraction."""

import re
from pathlib import Path
from typing import Any

from iocsearcher.document import open_document
from iocsearcher.searcher import Searcher

from odysafe_threatmap.domain.exceptions import InputFileError
from odysafe_threatmap.domain.models import ExtractedIndicator, ExtractedTTP, ExtractionResult
from odysafe_threatmap.utils.text import count_lines, count_words, line_number_at_offset

TTP_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")
SUPPORTED_REPORT_SUFFIXES = frozenset({".txt", ".html", ".htm", ".pdf", ".docx"})


def read_report_text(file_path: Path) -> str:
    """Extract readable text from a supported local report document."""
    path = Path(file_path)
    if str(path).casefold().startswith(("http:/", "https:/")):
        raise InputFileError(
            "Remote report URLs cannot be downloaded in offline analysis mode. "
            "Download the report first, then provide its local path."
        )
    if not path.is_file() or path.suffix.casefold() not in SUPPORTED_REPORT_SUFFIXES:
        formats = ", ".join(sorted(SUPPORTED_REPORT_SUFFIXES))
        raise InputFileError(f"Input report must be an existing local file ({formats}): {path}")
    try:
        if path.suffix.casefold() == ".txt":
            raw = path.read_bytes()
            encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
            return raw.decode(encoding)
        document = open_document(str(path))
        if document is None:
            raise InputFileError(f"iocsearcher does not support this report document: {path}")
        text, _method = document.get_text(options={"html_use_readability": False, "html_include_links": True})
        if not text:
            raise InputFileError(f"No readable text could be extracted from report: {path}")
        return str(text)
    except InputFileError:
        raise
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise InputFileError(f"Unable to read input report: {error}") from error


class IocsearcherAdapter:
    """Reuse one iocsearcher Searcher instance for all report extractions."""

    def __init__(self) -> None:
        self._searcher = Searcher()

    def extract(self, file_path: Path) -> ExtractionResult:
        """Extract deduplicated observables and explicit ATT&CK IDs from a report."""
        text = read_report_text(file_path)
        indicator_matches: dict[tuple[str, str], ExtractedIndicator] = {}
        ttp_matches: dict[str, ExtractedTTP] = {}
        for match in self._searcher.search_matches(text):
            self._collect_match(match, text, indicator_matches, ttp_matches)
        return ExtractionResult(
            indicators=sorted(indicator_matches.values(), key=lambda indicator: indicator.first_offset),
            ttps=sorted(ttp_matches.values(), key=lambda ttp: ttp.offsets[0]),
            word_count=count_words(text),
            line_count=count_lines(text),
        )

    def _collect_match(
        self,
        match: Any,
        text: str,
        indicators: dict[tuple[str, str], ExtractedIndicator],
        ttps: dict[str, ExtractedTTP],
    ) -> None:
        match_type = str(match.name)
        raw_value = str(match.raw_value)
        normalized_value = str(match.value)
        offset = int(match.start_offset)
        line = line_number_at_offset(text, offset)
        if match_type == "ttp":
            attack_id = normalized_value.upper()
            if TTP_PATTERN.fullmatch(attack_id):
                self._add_ttp(ttps, attack_id, offset, line)
            return
        key = (match_type, normalized_value)
        if key not in indicators:
            indicators[key] = ExtractedIndicator(
                type=match_type,
                normalized_value=normalized_value,
                raw_value=raw_value,
                defanged=bool(match.defanged),
                occurrences=1,
                first_offset=offset,
                first_line=line,
                lines=[line],
            )
            return
        indicator = indicators[key]
        indicator.occurrences += 1
        indicator.defanged = indicator.defanged or bool(match.defanged)
        if line not in indicator.lines:
            indicator.lines.append(line)

    @staticmethod
    def _add_ttp(ttps: dict[str, ExtractedTTP], attack_id: str, offset: int, line: int) -> None:
        if attack_id not in ttps:
            ttps[attack_id] = ExtractedTTP(attack_id=attack_id, occurrences=1, offsets=[offset], lines=[line])
            return
        ttp = ttps[attack_id]
        ttp.occurrences += 1
        ttp.offsets.append(offset)
        if line not in ttp.lines:
            ttp.lines.append(line)
