"""Explicit, network-enabled ATT&CK acquisition for data-management commands only."""

import re
import shutil
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from mitreattack import release_info
from mitreattack.download_stix import download_stix

from odysafe_threatmap.domain.exceptions import AttackDataInvalidError

MITRE_CTI_MASTER_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
MITRE_CTI_RELEASE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{release}/enterprise-attack/enterprise-attack.json"
)
_RELEASE_PATTERN = re.compile(r"^(?:MITRE\s+ATT&CK\s+release:\s*)?[vV]?(\d+\.\d+)$", re.IGNORECASE)


def normalize_release(value: str) -> str:
    """Return the canonical major.minor ATT&CK release identifier."""
    match = _RELEASE_PATTERN.fullmatch(value.strip())
    if match is None:
        raise AttackDataInvalidError(f"Invalid ATT&CK release: {value.strip() or 'empty value'}")
    return match.group(1)


def resolve_release_from_sha256(sha256: str) -> str | None:
    """Resolve an exact Enterprise release only when official metadata has the same hash."""
    return next(
        (release for release, known_hash in release_info.STIX20["enterprise"].items() if known_hash == sha256),
        None,
    )


def download_master(destination: Path) -> datetime:
    """Download the mutable MITRE CTI master snapshot to an explicit temporary path."""
    try:
        wget = shutil.which("wget")
        if wget is not None:
            subprocess.run(  # noqa: S603
                [wget, "--progress=bar:force:noscroll", "-O", str(destination), MITRE_CTI_MASTER_URL],
                check=True,
            )
            return datetime.now(timezone.utc)
        with urllib.request.urlopen(MITRE_CTI_MASTER_URL, timeout=60) as response:  # noqa: S310
            with Path(destination).open("wb") as target:
                shutil.copyfileobj(response, target)
    except (OSError, subprocess.CalledProcessError, urllib.error.URLError) as error:
        raise AttackDataInvalidError(f"Unable to download MITRE CTI master: {error}") from error
    return datetime.now(timezone.utc)


def download_release(release: str, destination_dir: Path) -> Path:
    """Download one reproducible Enterprise STIX 2.0 release with MITRE's library API."""
    release = normalize_release(release)
    releases = release_info.STIX20["enterprise"]
    if release not in releases:
        raise AttackDataInvalidError(f"Unknown Enterprise ATT&CK release: {release}")
    directory = Path(destination_dir)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"v{release}" / "enterprise-attack.json"
    try:
        wget = shutil.which("wget")
        if wget is not None:
            destination.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(  # noqa: S603
                [
                    wget,
                    "--progress=bar:force:noscroll",
                    "-O",
                    str(destination),
                    MITRE_CTI_RELEASE_URL.format(release=release),
                ],
                check=True,
            )
        else:
            download_stix("2.0", "enterprise", str(directory), release, releases[release])
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise AttackDataInvalidError(f"Unable to download Enterprise ATT&CK {release}: {error}") from error
    if destination.is_file():
        return destination
    candidates = sorted(directory.rglob("*.json"))
    if not candidates:
        raise AttackDataInvalidError("mitreattack-python did not produce an ATT&CK release bundle.")
    return candidates[0]
