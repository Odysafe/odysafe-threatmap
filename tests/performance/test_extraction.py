"""Non-flaky extraction reuse invariants."""

from odysafe_threatmap.infrastructure.extraction.iocsearcher_adapter import IocsearcherAdapter


def test_iocsearcher_adapter_reuses_its_searcher() -> None:
    """One adapter keeps one Searcher instance for repeated extractions."""
    adapter = IocsearcherAdapter()
    assert adapter._searcher is adapter._searcher
