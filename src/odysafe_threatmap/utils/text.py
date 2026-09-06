"""Deterministic text metrics and position helpers."""

import re


def count_words(text: str) -> int:
    """Return the number of non-whitespace word tokens in text."""
    return len(re.findall(r"\S+", text))


def count_lines(text: str) -> int:
    """Return the number of logical lines in text."""
    return len(text.splitlines())


def line_number_at_offset(text: str, offset: int) -> int:
    """Return the one-based line number containing a character offset."""
    return text.count("\n", 0, offset) + 1
