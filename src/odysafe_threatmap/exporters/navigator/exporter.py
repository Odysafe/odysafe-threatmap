"""ATT&CK Navigator layer generation using mitreattack.navlayers."""

import json
from pathlib import Path
from typing import Any

from mitreattack.navlayers import Layer

from odysafe_threatmap.application.navigator_service import NavigatorLayerData


def _layer(name: str, entries: list[dict[str, Any]], metadata: dict[str, str], description: str) -> Layer:
    scores = [entry["score"] for entry in entries] or [0]
    minimum = min(scores)
    maximum = max(scores)
    if minimum == maximum:
        maximum = minimum + 1
    payload = {
        "name": name,
        "domain": "enterprise-attack",
        "description": description,
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "techniques": entries,
        "gradient": {"colors": ["#ffffff", "#d73027"], "minValue": minimum, "maxValue": maximum},
        "metadata": [{"name": key, "value": value} for key, value in metadata.items()],
    }
    return Layer(payload)


def create_presence_layer(data: NavigatorLayerData) -> Layer:
    """Create a layer scoring every present technique as one."""
    return _layer(
        data.name,
        [{"techniqueID": item.attack_id, "score": 1} for item in data.techniques],
        data.metadata,
        "Technique presence",
    )


def create_frequency_layer(data: NavigatorLayerData) -> Layer:
    """Create a layer using normalized occurrence or group-frequency scores."""
    return _layer(
        data.name,
        [{"techniqueID": item.technique.attack_id, "score": item.frequency} for item in data.frequencies],
        data.metadata,
        "Technique frequency",
    )


def create_mitigations_layer(data: NavigatorLayerData) -> Layer:
    """Create a layer for ATT&CK-documented mitigations, not implementation state."""
    entries = [
        {"techniqueID": item.attack_id, "score": int(bool(item.mitigations)), "comment": "ATT&CK documented mitigation"}
        for item in data.techniques
    ]
    return _layer(data.name, entries, data.metadata, "ATT&CK documented mitigation")


def create_risk_layer(data: NavigatorLayerData) -> Layer:
    """Create a layer for Odysafe-local priority scores."""
    entries = [
        {"techniqueID": item.technique.attack_id, "score": item.priority_score, "comment": item.priority_label}
        for item in data.risks
    ]
    return _layer(data.name, entries, data.metadata, "Odysafe local prioritization")


def create_layer(data: NavigatorLayerData) -> Layer:
    """Create a layer selected by the application's format-neutral kind."""
    factories = {
        "presence": create_presence_layer,
        "frequency": create_frequency_layer,
        "mitigations": create_mitigations_layer,
        "risk": create_risk_layer,
    }
    return factories[data.kind](data)


def save_layer(layer: Layer, output_path: Path) -> Path:
    """Save a standard UTF-8 JSON layer and verify it reloads with navlayers."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(layer.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    loaded = Layer()
    loaded.from_file(str(output_path))
    if loaded.to_dict() is None:
        raise ValueError("Navigator layer could not be reloaded.")
    return output_path
