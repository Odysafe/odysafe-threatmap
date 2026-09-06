"""Spreadsheet cell value safety helpers."""

from typing import Any

FORMULA_PREFIXES = ("=", "+", "-", "@")


def escape_excel_value(value: Any) -> Any:
    """Return a safe value that cannot be interpreted as an Excel formula."""
    if isinstance(value, str) and value.startswith(FORMULA_PREFIXES):
        return f"'{value}"
    return value
