"""YAML configuration loading with optional user overrides."""

import hashlib
from collections.abc import Mapping
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

from odysafe_threatmap.config.schemas import (
    ActorMetadataConfig,
    ApplicationConfig,
    PriorityThresholds,
    TacticImpactConfig,
)


def load_yaml_config(path: Path) -> dict[str, Any]:
    """Load a mapping from a YAML file, returning an empty mapping when absent."""
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8") as config_file:
        data = yaml.safe_load(config_file) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Configuration file must contain a mapping: {path}")
    return data


def _merge_mappings(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = _merge_mappings(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_application_config(default_path: Path, user_override_path: Path | None = None) -> ApplicationConfig:
    """Load default YAML configuration and apply a user override when present."""
    defaults = load_yaml_config(default_path)
    overrides = load_yaml_config(user_override_path) if user_override_path else {}
    return ApplicationConfig.model_validate(_merge_mappings(defaults, overrides))


def load_actor_metadata(path: Path) -> ActorMetadataConfig:
    """Load the explicitly curated local actor metadata mapping."""
    return ActorMetadataConfig.model_validate(load_yaml_config(path))


def load_tactic_impact(path: Path) -> TacticImpactConfig:
    """Load local tactic impact weights."""
    return TacticImpactConfig.model_validate(load_yaml_config(path))


def load_priority_thresholds(path: Path) -> PriorityThresholds:
    """Load local Odysafe priority thresholds."""
    return PriorityThresholds.model_validate(load_yaml_config(path))


def compute_embedded_config_hash() -> str:
    """Return a deterministic hash of bundled YAML configuration files."""
    config_root = files("odysafe_threatmap.config")
    digest = hashlib.sha256()
    resources = [
        resource
        for directory in (config_root.joinpath("defaults"), config_root.joinpath("sectors"))
        for resource in directory.iterdir()
        if resource.name.endswith((".yaml", ".yml"))
    ]
    for resource in sorted(resources, key=lambda item: str(item)):
        digest.update(resource.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(resource.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()
