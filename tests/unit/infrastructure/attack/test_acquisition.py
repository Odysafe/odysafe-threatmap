"""Focused tests for official ATT&CK release acquisition."""

from pathlib import Path

import pytest

from odysafe_threatmap.domain.exceptions import AttackDataInvalidError
from odysafe_threatmap.infrastructure.attack import acquisition


@pytest.mark.parametrize(
    "value",
    ["19.2", "v19.2", "V19.2", " 19.2 ", "MITRE ATT&CK release: 19.2"],
)
def test_normalize_release(value: str) -> None:
    assert acquisition.normalize_release(value) == "19.2"


@pytest.mark.parametrize("value", ["", "release 19.2", "19", "19.2.1", "latest", "x19.2"])
def test_normalize_release_rejects_invalid_syntax(value: str) -> None:
    with pytest.raises(AttackDataInvalidError, match="Invalid ATT&CK release"):
        acquisition.normalize_release(value)


def test_release_resolver_passes_serialized_stix_version_2_0(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str, str]] = []

    def fake_download(stix_version: str, domain: str, directory: str, release: str, _hash: str) -> None:
        calls.append((stix_version, domain, release))
        target = Path(directory) / f"v{release}" / "enterprise-attack.json"
        target.parent.mkdir(parents=True)
        target.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(acquisition, "download_stix", fake_download)
    monkeypatch.setattr(acquisition.shutil, "which", lambda _command: None)

    path = acquisition.download_release("v19.2", tmp_path)

    assert calls == [("2.0", "enterprise", "19.2")]
    assert path.name == "enterprise-attack.json"


def test_requested_19_1_is_resolved_exactly_without_latest_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    releases: list[str] = []

    def fake_download(_stix: str, _domain: str, directory: str, release: str, _hash: str) -> None:
        releases.append(release)
        target = Path(directory) / f"v{release}" / "enterprise-attack.json"
        target.parent.mkdir(parents=True)
        target.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(acquisition, "download_stix", fake_download)
    monkeypatch.setattr(acquisition.shutil, "which", lambda _command: None)

    acquisition.download_release("19.1", tmp_path)

    assert releases == ["19.1"]


def test_unknown_release_fails_without_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        acquisition,
        "download_stix",
        lambda *_args: pytest.fail("network helper must not be called"),
    )
    with pytest.raises(AttackDataInvalidError, match="Unknown Enterprise ATT&CK release: 99.99"):
        acquisition.download_release("99.99", tmp_path)


def test_master_sha_resolves_only_against_official_release_metadata() -> None:
    known_hash = acquisition.release_info.STIX20["enterprise"]["19.2"]

    assert acquisition.resolve_release_from_sha256(known_hash) == "19.2"
    assert acquisition.resolve_release_from_sha256("0" * 64) is None
