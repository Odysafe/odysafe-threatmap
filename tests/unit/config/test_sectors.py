"""Tests for the file-backed sector registry."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from odysafe_threatmap.config.sectors import SectorRegistry
from odysafe_threatmap.domain.exceptions import SectorNotFoundError


def test_all_sector_files_load_with_unique_ids_and_aliases() -> None:
    registry = SectorRegistry.load()

    assert len(registry.definitions) == 8
    assert len({item.id for item in registry.definitions}) == 8
    assert registry.resolve("Finance") == "financial"
    assert registry.resolve(" finance ") == "financial"
    assert registry.resolve("FINANCE") == "financial"
    assert registry.resolve("financial") == "financial"
    assert registry.resolve("banque") == "financial"
    assert registry.resolve("Banking") == "financial"


def test_numeric_selection_supports_lists_ranges_spaces_and_deduplication() -> None:
    registry = SectorRegistry.load()

    assert registry.resolve_selection("1") == ["financial"]
    assert registry.resolve_selection("1,2") == ["financial", "energy"]
    assert registry.resolve_selection("1, 2, 5") == ["financial", "energy", "technology"]
    assert registry.resolve_selection("1,1,2") == ["financial", "energy"]
    assert registry.resolve_selection("1-4") == ["financial", "energy", "healthcare", "government"]


@pytest.mark.parametrize("selection", ["", "0", "99", "x", "3-1"])
def test_invalid_numeric_selection_is_rejected(selection: str) -> None:
    with pytest.raises(SectorNotFoundError):
        SectorRegistry.load().resolve_selection(selection)


def test_invalid_sector_file_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "broken.yaml").write_text("id: broken\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        SectorRegistry.load(tmp_path)


def test_ambiguous_alias_is_rejected(tmp_path: Path) -> None:
    template = "order: {order}\nid: {id}\nname: {name}\ndescription: test\naliases: [shared]\n"
    (tmp_path / "one.yaml").write_text(template.format(order=1, id="one", name="One"), encoding="utf-8")
    (tmp_path / "two.yaml").write_text(template.format(order=2, id="two", name="Two"), encoding="utf-8")
    with pytest.raises(ValueError, match="Ambiguous sector alias"):
        SectorRegistry.load(tmp_path)
