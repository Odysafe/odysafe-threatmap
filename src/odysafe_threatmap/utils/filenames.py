"""Safe deterministic output filename helpers."""

import re
from datetime import datetime
from pathlib import Path


def sanitize_filename(name: str) -> str:
    """Return a filesystem-safe filename component."""
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip())
    return sanitized.strip("._") or "output"


def generate_output_filename(prefix: str, name: str, extension: str, output_dir: Path | None = None) -> str:
    """Build a sanitized output filename and avoid a collision when possible."""
    normalized_extension = extension if extension.startswith(".") else f".{extension}"
    filename = f"{sanitize_filename(prefix)}_{sanitize_filename(name)}{normalized_extension}"
    if output_dir is None or not (Path(output_dir) / filename).exists():
        return filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{sanitize_filename(prefix)}_{sanitize_filename(name)}_{timestamp}{normalized_extension}"


def ensure_output_dir(output_dir: Path) -> Path:
    """Create and return an output directory."""
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path
