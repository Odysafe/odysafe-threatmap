"""Structured content for Analysis Studio feature guides."""

from dataclasses import dataclass


@dataclass(frozen=True)
class FeatureGuide:
    key: str
    icon: str
    title: str
    summary: str
    what_it_does: tuple[str, ...]
    required_inputs: tuple[str, ...]
    optional_inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    limitations: tuple[str, ...]
    examples: tuple[str, ...]
    expected_result: str


FEATURE_GUIDES = {
    "report": FeatureGuide(
        key="report",
        icon="📄",
        title="REPORT WORKBOOK",
        summary="Analyse one local CTI report using the installed MITRE ATT&CK snapshot.",
        what_it_does=(
            "Extracts explicit IOCs such as IP addresses, domains, URLs, emails, hashes, and CVEs.",
            "Validates explicit MITRE ATT&CK technique IDs and explicit actor identifiers locally.",
        ),
        required_inputs=("Choose one TXT, HTML, PDF, or DOCX report from the configured reports folder using Space.",),
        optional_inputs=("Report name, source, date, TLP, confidence, and custom output directory.",),
        outputs=("Excel dashboard, IOC details, ATT&CK TTPs, tactics, detections, mitigations, and provenance.",),
        limitations=(
            "Normal prose is never converted into ATT&CK techniques; explicit ATT&CK IDs are required.",
            "URLs contained in a local report are extracted as IOCs.",
            "Remote URLs are not downloaded in offline analysis mode. Download the document first and provide its local path.",
        ),
        examples=(
            "Place a file at odysafe-input/reports/acme-incident-2026-09.pdf.",
            "In the selector: press ↓ to highlight it, Space or Enter to select it, then Tab and Enter to run.",
            "Direct CLI equivalent: odysafe report build /path/to/acme-incident-2026-09.pdf",
        ),
        expected_result="1 Excel workbook: IOCs + ATT&CK TTPs + tactics + detections + mitigations + provenance",
    ),
    "actor": FeatureGuide(
        key="actor",
        icon="👤",
        title="ACTOR SNAPSHOT",
        summary="Query explicit MITRE ATT&CK knowledge about one or several threat groups.",
        what_it_does=(
            "Resolves exact group IDs, canonical names, or aliases and retrieves direct ATT&CK relationships.",
        ),
        required_inputs=("Choose one actor from the interactive ATT&CK group list using Space.",),
        optional_inputs=("Select several actors with Space to generate a comparison workbook.",),
        outputs=("Actor identity, aliases, direct techniques, software, campaigns, local metadata, and dashboard.",),
        limitations=(
            "Odysafe does not attribute actors from TTP similarity or infer geography/sectors from descriptions.",
            "Ambiguous aliases are never selected automatically.",
        ),
        examples=("APT29", "APT29, Kimsuky", "odysafe actor snapshot G0016 APT29"),
        expected_result="One actor workbook or one multi-actor comparison workbook",
    ),
    "sector": FeatureGuide(
        key="sector",
        icon="🏢",
        title="SECTOR PROFILE",
        summary="Build threat priorities for one or several configured industries.",
        what_it_does=("Combines local actor-sector mappings with direct ATT&CK techniques and local tactic weights.",),
        required_inputs=("One or more sectors selected from the live local configuration.",),
        optional_inputs=("Several sectors may be selected at once.",),
        outputs=(
            "Configured actors, techniques, tactics, local priorities, regions, and available defensive context.",
        ),
        limitations=("Sector membership comes only from explicit local configuration, never from ATT&CK prose.",),
        examples=("1,2,5", "1-4", "odysafe sector profile financial energy"),
        expected_result="One sector threat-profile Excel workbook per selected sector",
    ),
    "aggregate": FeatureGuide(
        key="aggregate",
        icon="🗂",
        title="AGGREGATE REPORTS",
        summary="Correlate explicit evidence across several local CTI reports.",
        what_it_does=("Finds exact duplicates, repeated IOCs/TTPs, and source-backed corroboration.",),
        required_inputs=(
            "Choose one or several TXT, HTML, PDF, or DOCX files from the configured reports folder using Space.",
        ),
        optional_inputs=("Recursive scan and a source-mapping CSV identifying original primary sources.",),
        outputs=("Aggregate dashboard, report inventory, duplicates, IOCs, TTPs, corroboration, and provenance.",),
        limitations=(
            "Multi-source means the same evidence is backed by at least two different mapped primary sources.",
            "False corroboration means repeated evidence maps to the same primary source.",
            "Without complete source mapping, corroboration remains indeterminate.",
        ),
        examples=(
            "Place cert-fr.html, vendor-report.pdf, and incident.docx in odysafe-input/reports/.",
            "Highlight each required file and press Space or Enter; selected files show a check mark.",
            "After selection, press Tab to highlight Run and Enter to start aggregation.",
        ),
        expected_result="1 aggregate Excel workbook: reports + duplicates + IOCs + TTPs + corroboration",
    ),
    "sigma": FeatureGuide(
        key="sigma",
        icon="🛡",
        title="SIGMA COVERAGE",
        summary="Compare explicit report TTPs with ATT&CK tags in local Sigma rules.",
        what_it_does=("Classifies each report technique as exact, parent/child partial, or not covered.",),
        required_inputs=(
            "One report selected from the configured reports folder using Space, plus a directory containing Sigma YAML rules.",
        ),
        optional_inputs=("Rule-detail export and strict parsing are available in the direct CLI.",),
        outputs=("Coverage dashboard, exact/partial/missing TTPs, matching rules, and detection gaps.",),
        limitations=("Only explicit ATT&CK tags are used; Sigma rule semantics are never inferred.",),
        examples=(
            "Select odysafe-input/reports/acme-incident.pdf, then use Sigma rules from odysafe-input/sigma/.",
            "Direct CLI equivalent: odysafe coverage sigma /path/to/acme-incident.pdf /path/to/sigma/",
        ),
        expected_result="1 Sigma coverage Excel workbook: covered + partial + missing TTPs + matching rules",
    ),
}
