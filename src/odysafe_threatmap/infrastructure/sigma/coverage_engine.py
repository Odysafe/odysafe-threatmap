"""Strict ATT&CK tag coverage engine for parsed Sigma rules."""

from odysafe_threatmap.domain.models import AttackTechnique, CoverageRecord, ExtractedTTP, SigmaRuleRecord


class SigmaCoverageEngine:
    """Match techniques strictly by normalized ATT&CK tags."""

    def __init__(self, sigma_rules: list[SigmaRuleRecord], tactic_weights: dict[str, int]) -> None:
        self._rules = sigma_rules
        self._weights = tactic_weights

    def analyze_coverage(self, ttps: list[AttackTechnique], report_ttps: list[ExtractedTTP]) -> list[CoverageRecord]:
        """Return exact, hierarchical, or absent coverage for every technique."""
        occurrences = {item.attack_id: item.occurrences for item in report_ttps if item.validated}
        records = []
        for technique in ttps:
            exact = tuple(rule.title for rule in self._rules if technique.attack_id in rule.attack_tags)
            related = tuple(
                rule.title
                for rule in self._rules
                if any(_related(technique.attack_id, tag) for tag in rule.attack_tags)
                and technique.attack_id not in rule.attack_tags
            )
            status = "exact" if exact else "partial" if related else "none"
            coverage_value = {"exact": 3, "partial": 2, "none": 1}[status]
            impact = self._weights.get(technique.tactics[0], 1) * 20 if technique.tactics else 20
            score = (4 - coverage_value) * 40 + impact + occurrences.get(technique.attack_id, 0)
            priority = (
                "🔴 Critical"
                if score >= 150
                else "🟠 High"
                if score >= 100
                else "🟡 Moderate"
                if score >= 50
                else "🟢 Low"
            )
            records.append(
                CoverageRecord(
                    technique, occurrences.get(technique.attack_id, 0), exact, related, status, priority, score
                )
            )
        return records


def _related(left: str, right: str) -> bool:
    """Return whether two ATT&CK tags are parent/child, never merely similar text."""
    return left.split(".")[0] == right.split(".")[0] and left != right
