"""Tests for deterministic Excel presentation helpers."""

from odysafe_threatmap.exporters.excel.display_text import (
    clean_attack_text,
    format_ioc_type,
    format_list,
    truncate_display_text,
)


def test_clean_attack_text_removes_markup_without_paraphrasing() -> None:
    """ATT&CK markup is mechanically removed from visible text."""
    value = clean_attack_text("<p>[PowerShell](https://example.test)</p> (Citation: source)")
    assert value == "PowerShell"


def test_truncation_respects_the_strict_final_limit() -> None:
    """The ellipsis is included within the caller's character limit."""
    assert truncate_display_text("one two three four", 10) == "one two…"
    assert len(truncate_display_text("one two three four", 10)) <= 10


def test_list_and_ioc_labels_are_display_only_transformations() -> None:
    """Display formatting preserves ordering and only translates known labels."""
    assert format_list(["APT29", "APT29", "Cozy Bear", "NOBELIUM"], 2) == "APT29 • Cozy Bear • + 1 autres"
    assert format_ioc_type("fqdn") == "Domaine"
