"""Offline integration tests for Navigator JSON layers."""

import json
from pathlib import Path

from mitreattack.navlayers import Layer

from odysafe_threatmap.application.navigator_service import NavigatorLayerData
from odysafe_threatmap.domain.models import AttackTechnique
from odysafe_threatmap.exporters.navigator.exporter import create_presence_layer, save_layer


def test_layer_is_saved_and_reloaded_by_navlayers(tmp_path: Path) -> None:
    """A generated Navigator layer is one valid JSON document."""
    technique = AttackTechnique("T1566.001", "attack-pattern--test", "Test technique")
    layer = create_presence_layer(NavigatorLayerData(name="test-presence", kind="presence", techniques=[technique]))
    path = save_layer(layer, tmp_path / "presence.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    loaded = Layer()
    loaded.from_file(str(path))
    assert payload["domain"] == "enterprise-attack"
    assert loaded.to_dict()["techniques"][0]["techniqueID"] == "T1566.001"
