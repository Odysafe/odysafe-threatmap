# 🛡️ Odysafe Threatmap

**Offline Cyber Threat Intelligence analysis powered by MITRE ATT&CK.**

Odysafe Threatmap helps CTI analysts turn local threat reports into clear, structured and auditable intelligence.

It works with local files, uses an installed MITRE ATT&CK dataset, and produces ready-to-use Excel workbooks and ATT&CK intelligence.

> **No LLM. No cloud analysis. No automatic attribution. No hidden guessing.**

---

## ✨ Why Odysafe?

Many CTI tools try to guess what a report means.

Odysafe takes a different approach.

It focuses on information that can be **verified, reproduced and audited**.

### 🔒 Offline analysis

Once MITRE ATT&CK data is installed, analysis is performed locally.

Your reports stay on your machine.

```text
Local report
     ↓
Odysafe
     ↓
Local MITRE ATT&CK
     ↓
Excel intelligence
```

Network access is only used for explicit ATT&CK data installation or updates.

It is announced before use.

---

### 🎯 No AI guessing

Odysafe does **not** invent ATT&CK mappings from normal text.

For example:

```text
PowerShell was executed
```

does **not** automatically become:

```text
T1059.001
```

The report must explicitly contain an ATT&CK ID for it to become report TTP evidence.

This makes results easier to understand, verify and reproduce.

---

### 🧠 Built on MITRE ATT&CK

Odysafe uses a local MITRE ATT&CK STIX dataset as its main intelligence source.

It can enrich explicit ATT&CK techniques with information such as:

* technique names
* tactics
* sub-techniques
* mitigations
* detection information
* data components
* threat groups
* software
* campaigns

The exact ATT&CK dataset used for an analysis is tracked with provenance information.

---

### 📊 Built for analysts, not developers

You do not need to write Python code.

Odysafe provides a guided terminal interface where you can select:

```text
📄 Reports
👤 Threat actors
🏢 Sectors
🗂 Multiple reports
🛡 Sigma rules
```

and generate structured Excel workbooks.

---

# 🚀 Main Use Cases

## 📄 1. Analyse a CTI Report

Use this when you receive a threat report from:

* CERT / CSIRT
* security vendor
* SOC
* internal investigation
* threat research team

Supported local report formats:

```text
TXT
HTML
PDF
DOCX
```

Odysafe extracts explicit CTI information such as:

* IP addresses
* domains
* URLs
* email addresses
* hashes
* CVEs
* ATT&CK technique IDs
* explicitly identified ATT&CK threat groups

Then it enriches the ATT&CK information using the local MITRE dataset.

### Input

```text
report.pdf
```

### Output

```text
📊 Excel dashboard
🌐 IOC details
🎯 ATT&CK techniques
🗺 Tactics
🔎 Detection information
🛡 Mitigations
👥 Related ATT&CK context
🔐 Technical provenance
```

Example:

```bash
odysafe report build ./report.pdf
```

---

## 👤 2. Investigate a Threat Actor

Use this when you already know the actor you want to study.

Examples:

```text
APT29
Kimsuky
G0016
```

Odysafe queries the local ATT&CK dataset and retrieves explicit relationships.

### You can explore

* ATT&CK group identity
* aliases
* direct techniques
* software
* explicitly attributed campaigns
* local sector metadata
* local region metadata

### Input

```text
APT29
```

### Output

```text
Actor intelligence Excel workbook
```

Example:

```bash
odysafe actor snapshot APT29
```

Odysafe does **not** attribute an actor because its TTPs look similar to another incident.

---

## 👥 3. Compare Threat Actors

Select several groups to compare them in one workbook.

Example:

```text
APT29
Kimsuky
OilRig
```

The comparison helps analysts understand:

* shared ATT&CK techniques
* different techniques
* software
* campaigns
* ATT&CK coverage differences

### Output

```text
actor_comparison_*.xlsx
```

This is useful for intelligence research and comparative threat analysis.

It is **not** an automatic attribution engine.

---

## 🏢 4. Build a Sector Threat Profile

Use this when your question is:

> What ATT&CK techniques should I care about for my industry?

Examples:

```text
Financial
Energy
Technology
Healthcare
Government
```

Odysafe combines:

```text
Local actor ↔ sector mappings
            +
MITRE ATT&CK actor relationships
            +
ATT&CK techniques and tactics
```

### Output

A threat-profile workbook containing information such as:

* relevant configured threat groups
* direct ATT&CK techniques
* tactics
* technique frequency
* priorities
* regional metadata
* mitigation and detection context

### Important

Odysafe does not read ATT&CK descriptions and guess which industry an actor targets.

Sector membership must come from explicit local configuration.

---

## 🗂️ 5. Aggregate Multiple CTI Reports

Use this when you have many reports and want to find repeated intelligence.

Example:

```text
reports/
├── cert-report.pdf
├── vendor-a.docx
├── vendor-b.html
└── internal-report.txt
```

Odysafe can identify:

* reports processed
* exact duplicate reports
* unique IOCs
* repeated IOCs
* unique TTPs
* repeated TTPs
* source provenance
* corroborated evidence

### Input

```bash
odysafe aggregate ./reports
```

### Output

```text
Aggregate Excel workbook
```

with:

```text
📊 Dashboard
📄 Report inventory
♻️ Duplicates
🌐 IOCs
🎯 ATT&CK techniques
🔗 Corroboration
🔐 Provenance
```

---

## 🔗 Primary-Source Corroboration

Seeing the same IOC in five files does not always mean five independent sources confirmed it.

For example:

```text
CERT report
    ↓
Blog A copies CERT
Blog B copies CERT
Blog C copies CERT
```

There are four files, but only one original source.

Odysafe can use a source-mapping CSV to distinguish this.

### Multi-source corroboration

```text
Same evidence
+
at least two different mapped primary sources
```

### False corroboration

```text
Repeated evidence
+
same original primary source
```

### Indeterminate

```text
Evidence is repeated
+
source mapping is missing or incomplete
```

This helps avoid overstating confidence just because the same information appears in several publications.

---

# 🛡️ 6. Check Sigma Detection Coverage

Use this when you have:

```text
a CTI report
+
local Sigma rules
```

Odysafe compares explicit ATT&CK techniques from the report with explicit ATT&CK tags found in your Sigma rules.

Example:

```text
Report
  T1059.001
  T1071.001
  T1105
       │
       ▼
Sigma rules
       │
       ▼
Coverage
```

Results can include:

```text
🟢 Exact coverage
🟡 Partial coverage
🔴 Not covered
```

### Output

An Excel workbook showing:

* techniques analysed
* matching Sigma rules
* exact coverage
* partial coverage
* detection gaps

### Important

Odysafe does not inspect Sigma rule logic and guess an ATT&CK technique.

Coverage is based on explicit ATT&CK tags.

---

# 🗺️ ATT&CK Navigator

Odysafe can also generate ATT&CK Navigator layers for supported analysis workflows.

Navigator layers are useful for:

* CTI briefings
* SOC reviews
* threat coverage
* purple-team preparation
* visual ATT&CK mapping

They can represent information such as:

```text
Presence
Frequency
Mitigation
Risk
```

depending on the analysis.

---

# 🔒 Privacy and Offline Design

Privacy is a core design goal.

During normal analysis:

```text
✅ Reports stay local
✅ MITRE ATT&CK is read locally
✅ Excel files are created locally
✅ Sigma rules stay local
✅ No cloud analysis is required
✅ No LLM is used
```

Remote URLs found inside reports are treated as intelligence indicators.

Odysafe does not automatically visit those URLs during offline analysis.

---

# 🧾 Deterministic Intelligence

The same:

```text
input reports
+
ATT&CK snapshot
+
Odysafe configuration
```

should produce the same intelligence result.

This makes Odysafe suitable for workflows where analysts need to know:

> Where did this information come from?

and:

> Can I reproduce this result later?

Generated workbooks include technical provenance information such as the ATT&CK dataset used for the analysis.

---

# ⚠️ What Odysafe Does Not Do

Odysafe is intentionally conservative.

It is **not**:

* an LLM CTI assistant
* an automatic threat attribution engine
* a SIEM
* a malware sandbox
* a full Threat Intelligence Platform
* a semantic ATT&CK prediction engine

It will not say:

```text
PowerShell mentioned
→ therefore T1059.001
```

It will not say:

```text
These TTPs look like APT29
→ therefore the attacker is APT29
```

It will not say:

```text
This description mentions banks
→ therefore the actor targets Finance
```

When structured evidence is unavailable, Odysafe prefers:

```text
N/A
UNKNOWN
INDETERMINATE
```

instead of inventing information.

---

# 🧭 Guided Analysis Studio

Run:

```bash
odysafe
```

and select:

```text
✦ ANALYSIS STUDIO

[1] 📄 REPORT WORKBOOK
    Analyse one local CTI report

[2] 👤 ACTOR SNAPSHOT
    Explore one or several ATT&CK groups

[3] 🏢 SECTOR PROFILE
    Build industry threat priorities

[4] 🗂 AGGREGATE REPORTS
    Find repeated evidence across reports

[5] 🛡 SIGMA COVERAGE
    Compare CTI TTPs with local Sigma rules
```

The guided interface shows:

* what each function does
* what input is required
* what output will be generated
* important limitations
* available local files

---

# 📁 Default Input Folders

The guided interface uses simple local input folders.

```text
odysafe-input/
├── reports/
└── sigma/
```

Place reports in:

```text
odysafe-input/reports/
```

Supported:

```text
.txt
.html
.htm
.pdf
.docx
```

Place Sigma rules in:

```text
odysafe-input/sigma/
```

Supported:

```text
.yml
.yaml
```

Direct CLI commands can also use other local paths.

---

# 📤 Outputs

Generated files are written to the Odysafe output directory.

Typical structure:

```text
odysafe-output/
├── report_example.xlsx
├── actor_APT29.xlsx
├── actor_comparison_*.xlsx
├── aggregate.xlsx
├── sigma_coverage_*.xlsx
├── navigator_*.json
└── sectors/
    └── sector_financial.xlsx
```

Odysafe does not silently overwrite an existing analysis file.

---

# 🛠️ MITRE ATT&CK Data

Odysafe uses a local MITRE ATT&CK dataset.

On setup, you can choose:

```text
1. Latest official dataset
2. A specific ATT&CK release
3. Configure it later
```

Downloading ATT&CK requires network access.

Odysafe asks before performing the download.

After installation, the dataset is validated and stored locally.

You can inspect the installed dataset with:

```bash
odysafe data status
```

and check installation health with:

```bash
odysafe doctor
```

---

# 🚀 Quick Start

After installation:

```bash
odysafe
```

The easiest way to use Odysafe is the guided interface.

For direct CLI use:

```bash
# Analyse one report
odysafe report build ./report.pdf

# Actor intelligence
odysafe actor snapshot APT29

# Aggregate several reports
odysafe aggregate ./reports

# Check installation
odysafe doctor

# Inspect ATT&CK data
odysafe data status
```

---

# 🧑‍💻 Typical CTI Workflow

A common workflow can look like this:

```text
                   Threat report
                        │
                        ▼
                📄 Report Workbook
                        │
              IOCs + explicit TTPs
                        │
          ┌─────────────┴─────────────┐
          │                           │
          ▼                           ▼
 👤 Actor Research              🛡 Sigma Coverage
          │                           │
          │                           ▼
          │                    Detection gaps
          │
          ▼
   ATT&CK context
```

With several reports:

```text
CERT report
Vendor report
Internal report
Research report
      │
      ▼
🗂 Aggregate Reports
      │
      ├── repeated IOCs
      ├── repeated TTPs
      ├── duplicates
      ├── corroboration
      └── provenance
```

For industry-focused intelligence:

```text
Local sector mappings
          +
   MITRE ATT&CK
          │
          ▼
 🏢 Sector Profile
```

---

# 🎯 Who Is It For?

Odysafe is designed for:

* CTI analysts
* SOC analysts
* detection engineers
* CERT / CSIRT teams
* blue teams
* purple teams
* security researchers

It is especially useful when you want a result that is:

```text
Local
Explainable
Repeatable
Auditable
ATT&CK-based
Easy to share
```

---

# 🧪 Health Check

Run:

```bash
odysafe doctor
```

Odysafe checks key components such as:

* Python
* MITRE ATT&CK support
* ATT&CK local data
* IOC extraction
* Excel export
* Sigma support
* Navigator support
* local configuration

---

# 🧱 Core Principles

Odysafe follows a few simple rules:

### 1. Evidence first

Do not create intelligence that is not supported by explicit evidence.

### 2. Local first

Keep CTI data and analysis on the analyst's machine.

### 3. ATT&CK as structured intelligence

Use MITRE ATT&CK relationships instead of guessing relationships from prose.

### 4. Reproducible results

Keep enough provenance to understand how a workbook was produced.

### 5. Useful outputs

Produce workbooks that analysts can review, filter, share and use in real investigations.

---

# 📌 Project Status

Odysafe Threatmap is under active development.

The project currently focuses on:

* reliable local CTI extraction
* MITRE ATT&CK enrichment
* actor intelligence
* sector threat profiling
* report correlation
* Sigma coverage
* analyst-friendly Excel workbooks
* deterministic and auditable results

---

## 🛡️ Odysafe Threatmap

**Turn local threat intelligence into structured ATT&CK intelligence — without sending your reports to the cloud and without asking an AI to guess what they mean.**

## ❤️ Acknowledgements

Odysafe Threatmap would not be possible without the work of the open-source cybersecurity community.

A special thank you to the developers, maintainers and contributors behind these projects:

* 🔎 **iocsearcher — MaliciaLab / IMDEA Software Institute**
  IOC and cyber-observable extraction from security reports.

* 🛡️ **MITRE ATT&CK**
  The knowledge base used by Odysafe to work with threat groups, techniques, tactics, software, campaigns, mitigations and detection information.

* 🐍 **mitreattack-python — MITRE ATT&CK**
  Python tools used to read, query and work with local MITRE ATT&CK STIX data.

* 🔗 **STIX — OASIS Cyber Threat Intelligence Technical Committee**
  The open standard for representing and exchanging structured Cyber Threat Intelligence.

* 📄 **txt2stix — DOGESEC**
  Open-source work around extracting cyber threat intelligence from reports and representing it as STIX.

* 🛡️ **Sigma**
  The open detection-rule ecosystem that makes portable detection engineering possible across many security platforms.

* 📊 **XlsxWriter**
  Used to create the Excel workbooks, dashboards, tables and charts generated by Odysafe.

* 🎨 **Rich**
  Used to build the readable, colored and interactive terminal interface.

* ⌨️ **Typer**
  Used to build the command-line interface.

Thank you to every maintainer and contributor who shares their work with the cybersecurity community.

Odysafe does not replace these projects. It brings them together in a local and analyst-focused workflow.

### Open-source projects

**iocsearcher** — GitHub
**MITRE ATT&CK** — Official website
**mitreattack-python** — GitHub
**STIX** — OASIS Open
**txt2stix** — GitHub
**Sigma** — SigmaHQ
**XlsxWriter** — Documentation
**Rich** — Documentation
**Typer** — Documentation

---

### Trademark notice

MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation.

Odysafe Threatmap is an independent project and is not affiliated with or endorsed by The MITRE Corporation, OASIS, MaliciaLab, DOGESEC, SigmaHQ, or the maintainers of the open-source projects listed above.

---

**Thank you to the open-source community for making tools like Odysafe possible. ❤️**
