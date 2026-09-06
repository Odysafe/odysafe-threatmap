"""Release metadata regression tests."""

import tomllib
from pathlib import Path


def test_release_metadata_keeps_the_lock_and_excludes_vendor_sources() -> None:
    """The sdist must remain reproducible without bundling vendor checkouts."""
    root = Path(__file__).parents[2]
    metadata = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["dynamic"] == ["version"]
    assert metadata["tool"]["hatch"]["version"]["path"] == "src/odysafe_threatmap/__init__.py"
    included = metadata["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
    excluded = metadata["tool"]["hatch"]["build"]["targets"]["sdist"]["exclude"]
    assert "uv.lock" in included
    assert all(vendor not in included for vendor in ("iocsearcher", "mitreattack-python", "txt2stix"))
    assert all(f"/{vendor}/**" in excluded for vendor in ("iocsearcher", "mitreattack-python", "txt2stix"))
