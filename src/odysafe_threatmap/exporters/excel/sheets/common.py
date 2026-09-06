"""Shared worksheet helpers for report bundle sheets."""

from typing import Any


def write_no_data_banner(sheet: Any, row: int, message: str = "ℹ Aucune donnée disponible.") -> None:
    """Write a visible, non-error banner for an intentionally empty sheet."""
    target = getattr(sheet, "worksheet", sheet)
    target.write(row, 0, message)
