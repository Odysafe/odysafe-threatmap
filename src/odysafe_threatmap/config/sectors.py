"""Central registry for explicit, file-backed sector definitions."""

from collections.abc import Iterable
from importlib.resources import files
from pathlib import Path

from odysafe_threatmap.config.loader import load_yaml_config
from odysafe_threatmap.config.schemas import SectorDefinition
from odysafe_threatmap.domain.exceptions import SectorNotFoundError


class SectorRegistry:
    """Load, validate, list, and resolve canonical sectors and aliases."""

    def __init__(self, definitions: Iterable[SectorDefinition]) -> None:
        self.definitions = tuple(definitions)
        if not self.definitions:
            raise ValueError("No sector definitions were loaded.")
        ids = [item.id for item in self.definitions]
        if len(ids) != len(set(ids)):
            raise ValueError("Sector IDs must be unique.")
        self._aliases: dict[str, str] = {}
        for item in self.definitions:
            for value in (item.id, item.name, *item.aliases):
                key = value.strip().casefold()
                previous = self._aliases.get(key)
                if previous is not None and previous != item.id:
                    raise ValueError(f"Ambiguous sector alias: {value}")
                self._aliases[key] = item.id

    @classmethod
    def load(cls, directory: Path | None = None) -> "SectorRegistry":
        root = directory or Path(str(files("odysafe_threatmap.config").joinpath("sectors")))
        definitions = [SectorDefinition.model_validate(load_yaml_config(path)) for path in sorted(root.glob("*.yaml"))]
        return cls(sorted(definitions, key=lambda item: (item.order, item.id)))

    def resolve(self, value: str) -> str:
        key = value.strip().casefold()
        result = self._aliases.get(key)
        if result is None:
            raise SectorNotFoundError(f'Sector not recognized: "{value.strip()}".')
        return result

    def resolve_many(self, values: Iterable[str]) -> list[str]:
        return list(dict.fromkeys(self.resolve(value) for value in values))

    def resolve_selection(self, value: str) -> list[str]:
        indexes: list[int] = []
        for part in value.split(","):
            token = part.strip()
            if not token:
                continue
            if "-" in token:
                bounds = token.split("-", 1)
                if len(bounds) != 2 or not all(item.strip().isdigit() for item in bounds):
                    raise SectorNotFoundError(f"Invalid sector selection: {token}")
                start, end = (int(item) for item in bounds)
                if start > end:
                    raise SectorNotFoundError(f"Invalid sector range: {token}")
                indexes.extend(range(start, end + 1))
            elif token.isdigit():
                indexes.append(int(token))
            else:
                raise SectorNotFoundError(f"Invalid sector selection: {token}")
        if not indexes:
            raise SectorNotFoundError("Select at least one sector.")
        if any(index < 1 or index > len(self.definitions) for index in indexes):
            raise SectorNotFoundError("Sector selection is outside the available range.")
        return list(dict.fromkeys(self.definitions[index - 1].id for index in indexes))
