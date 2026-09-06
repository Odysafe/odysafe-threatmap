"""SQLite indexes derived from a local ATT&CK bundle."""

import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from odysafe_threatmap.config.loader import compute_embedded_config_hash
from odysafe_threatmap.domain.exceptions import CacheInvalidError
from odysafe_threatmap.infrastructure.attack.loader import load_attack_data
from odysafe_threatmap.infrastructure.attack.metadata import compute_bundle_metadata

CACHE_SCHEMA_VERSION = "2"


def _field(value: Any, name: str, default: Any = None) -> Any:
    return value.get(name, default) if isinstance(value, dict) else getattr(value, name, default)


def _attack_id(value: Any) -> str | None:
    references = _field(value, "external_references", []) or []
    for reference in references:
        external_id = _field(reference, "external_id")
        if isinstance(external_id, str):
            return external_id.upper()
    return None


def _relationship_objects(entries: list[Any]) -> list[Any]:
    return [_field(entry, "object") for entry in entries if _field(entry, "object") is not None]


def _create_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE cache_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE attack_index (
            attack_id TEXT PRIMARY KEY,
            stix_id TEXT NOT NULL,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            tactics TEXT NOT NULL,
            groups_count INTEGER NOT NULL,
            software_count INTEGER NOT NULL,
            tactic_order INTEGER NOT NULL
        );
        CREATE TABLE group_index (
            attack_id TEXT PRIMARY KEY,
            stix_id TEXT NOT NULL,
            name TEXT NOT NULL,
            aliases TEXT NOT NULL
        );
        CREATE INDEX group_index_name ON group_index(name COLLATE NOCASE);
        """
    )


def build_cache(bundle_path: Path, db_path: Path) -> None:
    """Build an atomic SQLite index for a validated local ATT&CK bundle."""
    metadata = compute_bundle_metadata(bundle_path)
    data = load_attack_data(bundle_path)
    destination = Path(db_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_handle, temporary_name = tempfile.mkstemp(prefix=".attack-index-", dir=destination.parent)
    os.close(temporary_handle)
    Path(temporary_name).unlink(missing_ok=True)
    try:
        with sqlite3.connect(temporary_name) as connection:
            _create_schema(connection)
            connection.executemany(
                "INSERT INTO cache_metadata(key, value) VALUES (?, ?)",
                [
                    ("bundle_sha256", str(metadata["sha256"])),
                    ("bundle_path", str(metadata["bundle_path"])),
                    ("cache_version", CACHE_SCHEMA_VERSION),
                    ("configuration_hash", compute_embedded_config_hash()),
                ],
            )
            tactics_by_matrix = data.get_tactics_by_matrix()
            tactics = tactics_by_matrix.get("Enterprise ATT&CK") or data.get_tactics(remove_revoked_deprecated=True)
            tactic_positions = {str(_field(tactic, "id")): index for index, tactic in enumerate(tactics)}
            direct_groups_by_technique = data.get_related("intrusion-set", "uses", "attack-pattern", reverse=True)
            direct_software_by_technique = data.merge(
                data.get_related("malware", "uses", "attack-pattern", reverse=True),
                data.get_related("tool", "uses", "attack-pattern", reverse=True),
            )
            for technique in data.get_techniques(remove_revoked_deprecated=True):
                attack_id = _attack_id(technique)
                stix_id = _field(technique, "id")
                if not attack_id or not isinstance(stix_id, str):
                    continue
                technique_tactics = data.get_tactics_by_technique(stix_id)
                tactic_names = [str(_field(tactic, "name", "N/A")) for tactic in technique_tactics]
                tactic_order = min(
                    (
                        tactic_positions.get(str(_field(tactic, "id")), len(tactic_positions))
                        for tactic in technique_tactics
                    ),
                    default=0,
                )
                group_entries = direct_groups_by_technique.get(stix_id, [])
                software_entries = direct_software_by_technique.get(stix_id, [])
                connection.execute(
                    """
                    INSERT INTO attack_index VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        attack_id,
                        stix_id,
                        str(_field(technique, "name", "N/A")),
                        str(_field(technique, "type", "attack-pattern")),
                        json.dumps(tactic_names),
                        len(_relationship_objects(group_entries)),
                        len(_relationship_objects(software_entries)),
                        tactic_order,
                    ),
                )
            for group in data.get_groups(remove_revoked_deprecated=True):
                attack_id = _attack_id(group)
                stix_id = _field(group, "id")
                if not attack_id or not isinstance(stix_id, str):
                    continue
                aliases = [str(alias) for alias in (_field(group, "aliases", []) or [])]
                connection.execute(
                    "INSERT INTO group_index VALUES (?, ?, ?, ?)",
                    (attack_id, stix_id, str(_field(group, "name", "N/A")), json.dumps(aliases)),
                )
        Path(temporary_name).replace(destination)
    except (OSError, sqlite3.Error, ValueError) as error:
        Path(temporary_name).unlink(missing_ok=True)
        raise CacheInvalidError(f"Unable to build ATT&CK cache: {error}") from error


def invalidate_cache(db_path: Path) -> None:
    """Remove the cache at the explicit database path, if it exists."""
    Path(db_path).unlink(missing_ok=True)


def is_cache_valid(db_path: Path, bundle_sha256: str, configuration_hash: str | None = None) -> bool:
    """Return whether a cache matches bundle, schema, and relevant configuration identity."""
    path = Path(db_path)
    if not path.is_file():
        return False
    try:
        with sqlite3.connect(path) as connection:
            rows = dict(connection.execute("SELECT key, value FROM cache_metadata").fetchall())
        return (
            rows.get("bundle_sha256") == bundle_sha256
            and rows.get("cache_version") == CACHE_SCHEMA_VERSION
            and rows.get("configuration_hash") == (configuration_hash or compute_embedded_config_hash())
        )
    except sqlite3.Error:
        return False


def _query_one(db_path: Path, query: str, parameters: tuple[str, ...]) -> dict[str, Any] | None:
    if not Path(db_path).is_file():
        return None
    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(query, parameters).fetchone()
    return dict(row) if row else None


def get_technique_by_attack_id(db_path: Path, attack_id: str) -> dict[str, Any] | None:
    """Return one cached technique by its ATT&CK identifier."""
    record = _query_one(db_path, "SELECT * FROM attack_index WHERE attack_id = ?", (attack_id.upper(),))
    if record is not None:
        record["tactics"] = json.loads(record["tactics"])
    return record


def get_group_by_name(db_path: Path, name: str) -> list[dict[str, Any]]:
    """Return cached groups with an exact case-insensitive name match."""
    path = Path(db_path)
    if not path.is_file():
        return []
    with sqlite3.connect(path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("SELECT * FROM group_index WHERE name = ? COLLATE NOCASE", (name,)).fetchall()
    records = [dict(row) for row in rows]
    for record in records:
        record["aliases"] = json.loads(record["aliases"])
    return records
