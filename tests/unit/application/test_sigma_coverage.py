"""Unit tests for strict Sigma coverage."""

from odysafe_threatmap.domain.models import AttackTechnique, ExtractedTTP, SigmaRuleRecord
from odysafe_threatmap.infrastructure.sigma.coverage_engine import SigmaCoverageEngine


def test_exact_parent_and_no_coverage_are_distinct() -> None:
    """Only exact ATT&CK tags yield exact coverage."""
    exact = AttackTechnique("T1059.001", "attack-pattern--one", "PowerShell", tactics=("Execution",))
    other = AttackTechnique("T1566.001", "attack-pattern--two", "Spearphishing", tactics=("Initial Access",))
    rules = [SigmaRuleRecord("one.yml", "1", "Parent rule", "stable", "high", ("T1059",))]
    records = SigmaCoverageEngine(rules, {"Execution": 4}).analyze_coverage(
        [exact, other], [ExtractedTTP("T1059.001", 2, validated=True), ExtractedTTP("T1566.001", 1, validated=True)]
    )
    assert [item.status for item in records] == ["partial", "none"]
    assert records[0].exact_rules == ()
