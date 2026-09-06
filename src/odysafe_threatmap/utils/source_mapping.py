"""Explicit primary-source mapping used for multi-report corroboration."""

import csv
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel


class SourceMapping(BaseModel):
    """One report-to-primary-source mapping supplied by the user."""

    report: str
    source_name: str
    primary_source_id: str
    published_date: datetime | None = None


def load_source_mapping(csv_path: Path) -> dict[str, SourceMapping]:
    """Load a source mapping keyed by filename, including the documented short form."""
    with Path(csv_path).open(encoding="utf-8-sig", newline="") as source_file:
        reader = csv.DictReader(source_file)
        fields = set(reader.fieldnames or ())
        full = {"report", "source_name", "primary_source_id"}.issubset(fields)
        short = {"file", "primary_source"}.issubset(fields)
        if not (full or short):
            raise ValueError(
                "Source mapping CSV requires either file,primary_source or "
                "report,source_name,primary_source_id columns."
            )
        mappings: dict[str, SourceMapping] = {}
        for row in reader:
            report = (row.get("report") or row.get("file") or "").strip()
            primary = (row.get("primary_source_id") or row.get("primary_source") or "").strip()
            if not report or not primary:
                continue
            item = SourceMapping.model_validate(
                {
                    "report": report,
                    "source_name": (row.get("source_name") or primary).strip(),
                    "primary_source_id": primary,
                    "published_date": row.get("published_date") or None,
                }
            )
            mappings[item.report] = item
        return mappings
