"""Tests for spreadsheet formula-injection protection."""

import pytest

from odysafe_threatmap.exporters.excel.security import escape_excel_value


@pytest.mark.parametrize("value", ["=SUM(A1:A10)", "+A1", "-A1", "@A1"])
def test_escape_excel_value_prefixes_dangerous_strings(value: str) -> None:
    """Formula-like user input is explicitly stored as text."""
    assert escape_excel_value(value) == f"'{value}"


def test_escape_excel_value_keeps_safe_values_unchanged() -> None:
    """Non-formula values keep their original types."""
    assert escape_excel_value("safe text") == "safe text"
    assert escape_excel_value(42) == 42
