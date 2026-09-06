"""Platform-aware paths used by the application."""

from pathlib import Path

from platformdirs import user_cache_path, user_config_path, user_data_path

APPLICATION_NAME = "odysafe-threatmap"
BUNDLE_FILENAME = "enterprise-attack.json"
CACHE_FILENAME = "attack-index.sqlite"


def get_data_dir(create: bool = True) -> Path:
    """Return and create the local ATT&CK data directory."""
    path = user_data_path(APPLICATION_NAME) / "attack"
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def get_cache_dir(create: bool = True) -> Path:
    """Return and create the application cache directory."""
    path = user_cache_path(APPLICATION_NAME)
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def get_config_dir(create: bool = True) -> Path:
    """Return and create the application configuration directory."""
    path = user_config_path(APPLICATION_NAME)
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def get_attack_bundle_path(version: str | None = None, create: bool = True) -> Path:
    """Return the conventional path of an ATT&CK bundle.

    Installed bundles are versioned. Callers resolving the active bundle should
    use the manifest because a bundle version can be unavailable in source data.
    """
    directory = get_data_dir(create=create)
    return directory / version / BUNDLE_FILENAME if version else directory / BUNDLE_FILENAME


def get_cache_db_path(create: bool = True) -> Path:
    """Return the SQLite cache database path."""
    return get_cache_dir(create=create) / CACHE_FILENAME


def get_config_path(filename: str = "attack-manifest.json", create: bool = True) -> Path:
    """Return a path inside the user configuration directory."""
    return get_config_dir(create=create) / filename
