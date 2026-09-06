"""Application service that prepares normalized data for Navigator exporters."""

from pydantic import BaseModel, ConfigDict, Field

from odysafe_threatmap.application.actor_snapshot import ActorSnapshotResult
from odysafe_threatmap.application.report_bundle import ReportBundleResult
from odysafe_threatmap.application.sector_profile import SectorProfileResult
from odysafe_threatmap.domain.models import AttackTechnique, AttackTechniqueWithFrequency, AttackTechniqueWithRisk
from odysafe_threatmap.infrastructure.attack.repository import AttackRepository


class NavigatorOptions(BaseModel):
    """Requested Navigator layer types and their output directory."""

    output_directory: str = "./odysafe-output"
    presence: bool = True
    frequency: bool = True
    mitigations: bool = True


class NavigatorLayerData(BaseModel):
    """A format-neutral layer description consumed by the Navigator exporter."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    kind: str
    techniques: list[AttackTechnique]
    frequencies: list[AttackTechniqueWithFrequency] = Field(default_factory=list)
    risks: list[AttackTechniqueWithRisk] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


class NavigatorResult(BaseModel):
    """Format-neutral Navigator layers prepared from a module result."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    layers: list[NavigatorLayerData]


class NavigatorService:
    """Reuse normalized module results without knowing Navigator JSON details."""

    def __init__(self, attack_repo: AttackRepository) -> None:
        self._attack_repo = attack_repo

    def generate_from_report(self, report_result: ReportBundleResult, options: NavigatorOptions) -> NavigatorResult:
        """Prepare presence, report-frequency, and documented-mitigation layers."""
        occurrences = {
            item.attack_id: item.occurrences for item in report_result.extraction_result.ttps if item.validated
        }
        frequencies = [
            AttackTechniqueWithFrequency(item, occurrences.get(item.attack_id, 0)) for item in report_result.techniques
        ]
        return self._result("report", report_result.techniques, frequencies, [], options)

    def generate_from_actor(self, actor_result: ActorSnapshotResult, options: NavigatorOptions) -> NavigatorResult:
        """Prepare presence, popularity, and documented-mitigation layers."""
        frequencies = [
            AttackTechniqueWithFrequency(item, actor_result.technique_popularity.get(item.stix_id, 0))
            for item in actor_result.techniques
        ]
        return self._result("actor", actor_result.techniques, frequencies, [], options)

    def generate_from_sector(self, sector_result: SectorProfileResult, options: NavigatorOptions) -> NavigatorResult:
        """Prepare presence, sector-frequency, and local-risk layers."""
        techniques = [item.technique for item in sector_result.techniques]
        frequencies = [
            AttackTechniqueWithFrequency(item.technique, round(item.sector_groups_percent))
            for item in sector_result.techniques
        ]
        by_id = {item.technique_id: item for item in sector_result.risk_matrix}
        risks = [
            AttackTechniqueWithRisk(item, by_id[item.attack_id].priority_score, by_id[item.attack_id].priority_label)
            for item in techniques
            if item.attack_id in by_id
        ]
        layers = self._result("sector", techniques, frequencies, risks, options).layers
        return NavigatorResult(
            layers=[item for item in layers if item.kind != "mitigations"]
            + (
                [
                    NavigatorLayerData(
                        name="sector-risk",
                        kind="risk",
                        techniques=techniques,
                        risks=risks,
                        metadata={"description": "Odysafe local prioritization"},
                    )
                ]
                if options.frequency
                else []
            )
        )

    @staticmethod
    def _result(
        source: str,
        techniques: list[AttackTechnique],
        frequencies: list[AttackTechniqueWithFrequency],
        risks: list[AttackTechniqueWithRisk],
        options: NavigatorOptions,
    ) -> NavigatorResult:
        layers = []
        if options.presence:
            layers.append(NavigatorLayerData(name=f"{source}-presence", kind="presence", techniques=techniques))
        if options.frequency:
            layers.append(
                NavigatorLayerData(
                    name=f"{source}-frequency", kind="frequency", techniques=techniques, frequencies=frequencies
                )
            )
        if options.mitigations:
            layers.append(NavigatorLayerData(name=f"{source}-mitigations", kind="mitigations", techniques=techniques))
        return NavigatorResult(layers=layers)
