"""Tests for the thin interactive CLI dispatcher."""

import io
import time
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest
import typer
from rich.console import Console
from typer.testing import CliRunner

from odysafe_threatmap.cli import interactive
from odysafe_threatmap.cli.app import app
from odysafe_threatmap.domain.exceptions import AmbiguousActorError


def _reader(values: list[str]) -> interactive.Reader:
    iterator: Iterator[str] = iter(values)
    return lambda _prompt: next(iterator)


def test_no_subcommand_opens_menu_and_quits() -> None:
    result = CliRunner().invoke(app, input="6\n")

    assert result.exit_code == 0
    assert "ODYSAFE" in result.output
    assert "INSPECT MITRE DATA" in result.output


def test_invalid_choice_is_retried() -> None:
    output: list[str] = []

    assert interactive.run_interactive(_reader(["", "invalid", "6"]), output.append) == 0
    assert output.count("Invalid choice.") == 2


def test_inspect_reuses_existing_handlers(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(interactive.data, "status", lambda: calls.append("status"))
    monkeypatch.setattr(interactive.data, "inspect_bundle", lambda _path: calls.append("inspect"))

    assert interactive.run_interactive(_reader(["1", "6"]), lambda _message: None) == 0
    assert calls == ["status", "inspect"]


def test_eof_and_keyboard_interrupt_exit_cleanly() -> None:
    for error in (EOFError(), KeyboardInterrupt()):
        messages: list[str] = []

        def stop(_prompt: str, failure: BaseException = error) -> str:
            raise failure

        assert interactive.run_interactive(stop, messages.append) == 0
        assert messages[-1] == "\nGoodbye."


def test_update_requires_explicit_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(interactive.data, "update", lambda: calls.append("network"))

    interactive.run_interactive(_reader(["2", "n", "6"]), lambda _message: None)
    assert calls == []
    interactive.run_interactive(_reader(["2", "yes", "6"]), lambda _message: None)
    assert calls == ["network"]


def test_release_install_normalizes_before_existing_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    releases: list[str | None] = []
    monkeypatch.setattr(interactive.data, "install", lambda _path, release: releases.append(release))

    interactive.run_interactive(
        _reader(["3", "MITRE ATT&CK release: v19.2", "y", "6"]),
        lambda _message: None,
    )

    assert releases == ["19.2"]


def test_sector_menu_uses_numeric_registry_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    selected: list[list[str]] = []
    monkeypatch.setattr(
        interactive.sector,
        "profile",
        lambda names, _output, _navigator, _regions: selected.append(names) or [],
    )

    interactive.run_interactive(_reader(["4", "3", "1", "1, 2, 1", "1", "6", "6"]), lambda _message: None)

    assert selected == [["financial", "energy"]]


def test_sector_menu_has_ascii_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    output: list[str] = []
    monkeypatch.setattr(interactive, "_unicode_supported", lambda: False)

    assert interactive._sector_selection(_reader(["1"]), output.append) == ["financial"]
    assert any("-" in line and "Finance" in line for line in output)


def test_activity_bar_animates_and_finishes_without_fake_percentage(monkeypatch: pytest.MonkeyPatch) -> None:
    output = io.StringIO()
    monkeypatch.setattr(
        interactive,
        "_console",
        Console(file=output, force_terminal=True, color_system=None, width=100),
    )

    interactive._run_with_progress("Working", lambda: time.sleep(0.2), interactive._styled_write)

    rendered = output.getvalue()
    assert "done" in rendered
    assert "█████" in rendered
    assert "%" not in rendered


@pytest.mark.parametrize("feature", ["report", "actor", "sector", "aggregate", "sigma"])
def test_each_feature_has_a_complete_guide(feature: str) -> None:
    output: list[str] = []

    assert interactive._feature_guide(interactive.FEATURE_GUIDES[feature], _reader(["2"]), output.append) is False
    visible = "\n".join(output)
    for section in (
        "WHAT THIS DOES",
        "WHAT YOU NEED",
        "OPTIONAL INPUT",
        "WHAT YOU GET",
        "IMPORTANT LIMITATIONS",
        "EXAMPLE",
        "EXPECTED RESULT",
        "← Back",
    ):
        assert section in visible


def test_analysis_studio_menu_explains_inputs_and_outputs() -> None:
    output: list[str] = []

    interactive._analysis_menu(_reader(["6"]), output.append)

    visible = "\n".join(output)
    assert "ANALYSIS STUDIO" in visible
    assert all(title in visible for title in ("REPORT WORKBOOK", "ACTOR SNAPSHOT", "SECTOR PROFILE"))
    assert visible.count("Input:") == 5
    assert visible.count("Output:") == 5


def test_analysis_studio_shows_default_input_locations_and_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports = tmp_path / "odysafe-input" / "reports"
    sigma = tmp_path / "odysafe-input" / "sigma"
    reports.mkdir(parents=True)
    sigma.mkdir(parents=True)
    (reports / "incident.pdf").write_bytes(b"%PDF-1.7")
    (reports / "ignored.csv").write_text("not a report", encoding="utf-8")
    (sigma / "process.yml").write_text("title: Process rule", encoding="utf-8")
    monkeypatch.setattr(interactive, "DEFAULT_REPORT_DIRECTORY", reports)
    monkeypatch.setattr(interactive, "DEFAULT_SIGMA_DIRECTORY", sigma)
    output: list[str] = []

    interactive._analysis_menu(_reader(["6"]), output.append)

    visible = "\n".join(output)
    assert "DEFAULT INPUT LOCATIONS" in visible
    assert str(reports.resolve()) in visible
    assert str(sigma.resolve()) in visible
    assert "incident.pdf" in visible
    assert "process.yml" in visible
    assert "ignored.csv" not in visible
    assert "Guided mode lists these files for keyboard selection" in visible
    assert "Direct commands accept other paths" in visible


def test_path_input_retries_invalid_file_and_supports_back(tmp_path: Path) -> None:
    report = tmp_path / "report.txt"
    report.write_text("T1059", encoding="utf-8")
    output: list[str] = []

    selected = interactive._path_input(
        _reader([str(tmp_path / "missing.txt"), str(report)]),
        output.append,
        title="REPORT INPUT",
        prompt="Report",
        kind="text report",
    )

    assert selected == report
    assert "REPORT NOT FOUND OR UNSUPPORTED FORMAT" in "\n".join(output)
    assert (
        interactive._path_input(_reader(["back"]), output.append, title="SIGMA", prompt="Directory", kind="directory")
        is None
    )


def test_path_input_reports_missing_sigma_directory(tmp_path: Path) -> None:
    output: list[str] = []

    assert (
        interactive._path_input(
            _reader([str(tmp_path / "missing-sigma"), "back"]),
            output.append,
            title="SIGMA RULE DIRECTORY",
            prompt="Sigma directory",
            kind="directory",
        )
        is None
    )
    assert "DIRECTORY NOT FOUND" in "\n".join(output)


def test_default_report_directory_selects_its_only_text_report(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    expected = reports / "only-report.txt"
    expected.write_text("T1059", encoding="utf-8")

    selected = interactive._path_input(
        _reader([""]),
        lambda _message: None,
        title="REPORT INPUT",
        prompt="Report",
        kind="text report",
        default=reports,
    )

    assert selected == expected


def test_pdf_is_accepted_as_a_supported_report_format(tmp_path: Path) -> None:
    pdf = tmp_path / "report.pdf"
    pdf.write_bytes(b"%PDF-1.7")
    output: list[str] = []

    assert (
        interactive._path_input(
            _reader([str(pdf)]),
            output.append,
            title="REPORT INPUT",
            prompt="Report",
            kind="text report",
        )
        == pdf
    )
    assert "TXT, HTML, PDF, or DOCX" in "\n".join(output)


def test_report_selector_lists_supported_files_and_returns_multiple_choices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = tmp_path / "alpha.txt"
    second = tmp_path / "bravo.pdf"
    ignored = tmp_path / "notes.csv"
    first.write_text("T1059", encoding="utf-8")
    second.write_bytes(b"%PDF-1.7")
    ignored.write_text("ignored", encoding="utf-8")
    captured: dict[str, object] = {}

    def dialog(**kwargs: object) -> object:
        captured.update(kwargs)
        return SimpleNamespace(run=lambda: [str(first), str(second)])

    monkeypatch.setattr(interactive, "checkboxlist_dialog", dialog)

    assert interactive._select_report_files(tmp_path, lambda _message: None) == [first, second]
    values = captured["values"]
    assert values == [(str(first), "alpha.txt"), (str(second), "bravo.pdf")]


def test_report_selector_handles_empty_directory_without_traceback(tmp_path: Path) -> None:
    output: list[str] = []

    assert interactive._select_report_files(tmp_path, output.append) is None
    assert "NO SUPPORTED REPORTS FOUND" in "\n".join(output)


def test_single_report_selector_uses_space_enabled_radio_dialog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = tmp_path / "incident.docx"
    report.write_bytes(b"document")
    captured: dict[str, object] = {}

    def dialog(**kwargs: object) -> object:
        captured.update(kwargs)
        return SimpleNamespace(run=lambda: str(report))

    monkeypatch.setattr(interactive, "radiolist_dialog", dialog)

    assert interactive._select_report_files(tmp_path, lambda _message: None, multiple=False) == [report]
    assert "Space or Enter selects" in str(captured["text"])


def test_sector_selector_uses_configured_values(monkeypatch: pytest.MonkeyPatch) -> None:
    definitions = [
        SimpleNamespace(id="financial", name="Financial Services"),
        SimpleNamespace(id="energy", name="Energy"),
    ]
    monkeypatch.setattr(
        interactive.SectorRegistry,
        "load",
        staticmethod(lambda: SimpleNamespace(definitions=definitions)),
    )
    captured: dict[str, object] = {}

    def dialog(**kwargs: object) -> object:
        captured.update(kwargs)
        return SimpleNamespace(run=lambda: ["financial", "energy"])

    monkeypatch.setattr(interactive, "checkboxlist_dialog", dialog)

    assert interactive._select_sectors(lambda _message: None) == ["financial", "energy"]
    assert captured["values"] == [
        ("financial", "Financial Services  (financial)"),
        ("energy", "Energy  (energy)"),
    ]


def test_sigma_rule_selector_lists_yaml_recursively(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    nested = tmp_path / "windows"
    nested.mkdir()
    rule = nested / "powershell.yml"
    rule.write_text("title: PowerShell", encoding="utf-8")
    (tmp_path / "ignored.txt").write_text("ignored", encoding="utf-8")
    captured: dict[str, object] = {}

    def dialog(**kwargs: object) -> object:
        captured.update(kwargs)
        return SimpleNamespace(run=lambda: [str(rule)])

    monkeypatch.setattr(interactive, "checkboxlist_dialog", dialog)

    assert interactive._select_sigma_rules(tmp_path, lambda _message: None) == [rule]
    assert captured["values"] == [(str(rule), "windows/powershell.yml")]


def test_guided_output_directory_is_absolute() -> None:
    assert interactive.DEFAULT_OUTPUT_DIRECTORY.is_absolute()


def test_report_workflow_shows_actual_completion_metrics(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    report_path = tmp_path / "report.txt"
    report_path.write_text("T1059 example.com", encoding="utf-8")
    generated = tmp_path / "report_report.xlsx"
    result = SimpleNamespace(
        report_metadata=SimpleNamespace(filename="report.txt"),
        extraction_result=SimpleNamespace(indicators=[object()], ttps=[object()]),
        detected_actors=[],
    )
    monkeypatch.setattr(interactive.report, "build", lambda *_args: (result, generated))
    output: list[str] = []

    interactive._report_workflow(
        _reader(["1", str(report_path), "", "", "", "", "", str(tmp_path), "1"]), output.append
    )

    visible = "\n".join(output)
    assert "ANALYSIS COMPLETE" in visible
    assert "Unique IOCs" in visible
    assert "ATT&CK techniques" in visible
    assert "GENERATED FILE" in visible
    assert str(generated) in visible
    assert "Human-readable title shown in the workbook" in visible
    assert "September 2026 intrusion investigation" in visible
    assert "Organization that published or supplied the report" in visible
    assert "2026-09-05" in visible
    assert "Odysafe does not calculate it" in visible


def test_actor_workflow_accepts_actor_list_at_guide_prompt(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    received: list[list[str]] = []
    generated = tmp_path / "actor_comparison.xlsx"
    result = SimpleNamespace(actors=[object(), object()], techniques=[], software=[], campaigns=[])

    def snapshot(actor_ids: list[str], *_args: object) -> tuple[object, Path]:
        received.append(actor_ids)
        return result, generated

    monkeypatch.setattr(interactive.actor, "snapshot", snapshot)
    output: list[str] = []

    interactive._actor_workflow(_reader(["APT29, Kimsuky", "1"]), output.append)

    assert received == [["APT29", "Kimsuky"]]
    assert "ACTOR COMPARISON COMPLETE" in "\n".join(output)


def test_empty_sector_configuration_is_a_readable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    output: list[str] = []
    monkeypatch.setattr(
        interactive.SectorRegistry,
        "load",
        staticmethod(lambda: (_ for _ in ()).throw(ValueError("empty"))),
    )

    assert interactive._sector_selection(_reader([]), output.append) is None
    assert "SECTOR CONFIGURATION UNAVAILABLE" in "\n".join(output)


def test_actor_ambiguity_is_reported_without_a_traceback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    bundle = tmp_path / "attack.json"
    bundle.write_text("{}", encoding="utf-8")
    output = io.StringIO()

    class AmbiguousService:
        def __init__(self, _repository: object) -> None:
            pass

        def build_snapshot(self, _identifiers: list[str], _options: object) -> object:
            raise AmbiguousActorError("Ambiguous actor identifier 'Shared Alias': G0001, G0002.")

    monkeypatch.setattr(interactive.actor, "load_manifest", lambda: SimpleNamespace(bundle_path=bundle))
    monkeypatch.setattr(interactive.actor, "AttackRepositoryImpl", lambda _path: object())
    monkeypatch.setattr(interactive.actor, "ActorSnapshotService", AmbiguousService)
    monkeypatch.setattr(interactive.actor, "console", Console(file=output, color_system=None))

    with pytest.raises(typer.Exit):
        interactive.actor.snapshot(["Shared Alias"], tmp_path, False, False, False)

    assert "Ambiguous actor identifier" in output.getvalue()
    assert "Traceback" not in output.getvalue()
