"""Domain-specific exceptions."""


class AttackDataError(Exception):
    """Base exception for local ATT&CK data failures."""


class AttackDataNotInstalledError(AttackDataError):
    """Raised when no local ATT&CK bundle is installed."""


class AttackDataInvalidError(AttackDataError):
    """Raised when a local ATT&CK bundle or manifest is invalid."""


class CacheInvalidError(AttackDataError):
    """Raised when an ATT&CK cache cannot be used."""


class InputFileError(Exception):
    """Raised when an input report cannot be read as supported text."""


class OfflinePolicyViolation(Exception):
    """Raised when an extraction request violates the offline policy."""


class ActorNotFoundError(Exception):
    """Raised when an exact actor identifier, name, or alias is not found."""


class AmbiguousActorError(Exception):
    """Raised when an exact actor query matches multiple candidates."""


class SectorNotFoundError(Exception):
    """Raised when an exact local sector mapping cannot be found."""
