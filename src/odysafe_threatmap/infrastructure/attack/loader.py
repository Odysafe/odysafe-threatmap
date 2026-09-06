"""Process-local lazy loading for MITRE ATT&CK STIX data."""

from pathlib import Path

from mitreattack.stix20 import MitreAttackData

from odysafe_threatmap.domain.exceptions import AttackDataInvalidError
from odysafe_threatmap.infrastructure.attack.capabilities import (
    detect_bundle_capabilities,
    verify_library_capabilities,
)

_LOADED_DATA: dict[Path, MitreAttackData] = {}


def load_attack_data(bundle_path: Path) -> MitreAttackData:
    """Load a local STIX 2.0 bundle once per resolved path and process."""
    path = Path(bundle_path).resolve()
    if not path.is_file():
        raise AttackDataInvalidError(f"ATT&CK bundle does not exist: {path}")
    if path not in _LOADED_DATA:
        detect_bundle_capabilities(path)
        verify_library_capabilities()
        try:
            _LOADED_DATA[path] = MitreAttackData(stix_filepath=str(path))
        except Exception as error:
            raise AttackDataInvalidError(f"Unable to load ATT&CK bundle: {error}") from error
    return _LOADED_DATA[path]


def clear_loaded_attack_data() -> None:
    """Clear process-local data used by tests and controlled reloads."""
    _LOADED_DATA.clear()
