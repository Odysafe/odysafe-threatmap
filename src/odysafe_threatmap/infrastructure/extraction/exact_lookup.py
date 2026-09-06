"""Exact ATT&CK identifier normalization and validation."""

import re

from odysafe_threatmap.infrastructure.attack.repository import AttackRepository

TTP_IDENTIFIER_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def normalize_ttp_id(attack_id: str) -> str:
    """Normalize an explicit ATT&CK technique identifier to uppercase."""
    normalized = attack_id.strip().upper()
    return normalized if TTP_IDENTIFIER_PATTERN.fullmatch(normalized) else normalized


def validate_ttp_id(attack_id: str, attack_repo: AttackRepository) -> bool:
    """Return whether an explicit ATT&CK ID resolves in the local repository."""
    normalized = normalize_ttp_id(attack_id)
    return (
        TTP_IDENTIFIER_PATTERN.fullmatch(normalized) is not None and attack_repo.get_technique(normalized) is not None
    )
