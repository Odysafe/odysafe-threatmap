"""Safe parser for local Sigma rules."""

import re
from pathlib import Path
from typing import Any

import yaml

from odysafe_threatmap.domain.models import SigmaRuleRecord

_ATTACK_TAG = re.compile(r"^attack\.t(\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def _attack_tags(tags: object) -> tuple[str, ...]:
    """Extract only normalized ATT&CK technique tags."""
    values = tags if isinstance(tags, list) else []
    return tuple(
        match.group(1).upper().join(("T", ""))
        for tag in values
        if isinstance(tag, str)
        if (match := _ATTACK_TAG.match(tag))
    )


def parse_sigma_rules(source: Path | list[Path]) -> list[SigmaRuleRecord]:
    """Parse selected rules or a directory without executing detection logic."""
    rules: list[SigmaRuleRecord] = []
    paths = (
        sorted(path for path in source if path.suffix.casefold() in {".yml", ".yaml"})
        if isinstance(source, list)
        else sorted([*Path(source).rglob("*.yml"), *Path(source).rglob("*.yaml")])
    )
    for path in paths:
        try:
            payload: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("Sigma YAML must contain a mapping.")
            rules.append(
                SigmaRuleRecord(
                    str(path),
                    str(payload["id"]) if payload.get("id") else None,
                    str(payload.get("title", "N/A")),
                    str(payload.get("status", "N/A")),
                    str(payload.get("level", "N/A")),
                    _attack_tags(payload.get("tags")),
                )
            )
        except (OSError, ValueError, yaml.YAMLError) as error:
            rules.append(SigmaRuleRecord(str(path), None, "N/A", "N/A", "N/A", (), (str(error),)))
    return rules
