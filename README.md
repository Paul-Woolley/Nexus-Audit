# Nexus-Audit

**Security Log Analysis & IT Audit Reporting Framework**

Transforming raw log data into defensible, risk-rated audit intelligence aligned with industry control frameworks.

---

## Overview

Nexus‑Audit is a modular, CLI‑based security auditing system engineered for IT auditors, risk professionals, and security teams. It bridges the gap between technical log analysis and executive‑ready audit reporting by:

- **Automating** detection of security control failures across authentication, network, and system integrity domains.
- **Standardizing** findings against MITRE ATT&CK tactics and IIA audit standards.
- **Delivering** multi‑format outputs (Markdown, JSON, CSV) for diverse stakeholder communication.
- **Ensuring** complete audit trail documentation for regulatory defensibility.

---

## Key Capabilities

| Feature | Business Value |
|---------|----------------|
| **Multi‑Format Log Ingestion** | Syslog, Apache, ISO 8601, and generic text parsing eliminates manual data normalization. |
| **Declarative YAML Rule Engine** | Audit logic codified as version‑controlled rules—enabling repeatable, defensible assessments. |
| **Risk‑Based Prioritization** | Automated severity scoring with MITRE ATT&CK mapping for threat‑informed risk response. |
| **Audit‑Ready Reporting** | Executive summaries, detailed findings with evidence, and remediation guidance. |
| **Complete Audit Trail** | Execution logging ensures tool accountability and supports quality assurance reviews. |

---

## Quick Start

```bash
# 1. Clone repository
git clone https://github.com/yourusername/nexus-audit.git
cd nexus-audit

# 2. Create virtual environment
python3 -m venv venv && source venv/bin/activate   # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Execute baseline audit scan
python nexus-audit.py scan \
    --log-file sample_logs/auth.log \
    --rules rules/ \
    --org "Your Organization" \
    --format all
```
---

**Output:** 
Structured findings in ```output/reports/scan_YYYYMMDD_HHMMSS/``` including executive report, machine‑readable JSON, and CSV for analysis.

## Command Reference
### Core Operations
| Command | Purpose | Use Case |
|---------|---------|----------|
| `scan` | Ingest logs, apply detection rules, generate findings | Primary audit execution |
| `report` | Regenerate reports from existing JSON findings | Report customization without re‑scanning |
| `list-rules` | Display loaded detection rules with metadata | Audit planning and scope validation |


### Scan Options
```bash
python nexus-audit.py scan \
    --log-file PATH          # Single log file
    --log-dir PATH           # Directory of .log/.txt files
    --rules PATH             # YAML rule directory (default: rules/)
    --org "Name"             # Organization for report headers
    --format {markdown,json,csv,all}
    --output-dir PATH        # Custom output location
```
---
## Architecture
nexus-audit/
├── nexus-audit.py          # CLI entry point
├── engine/                 # Core audit engine
│   ├── ingestion.py        # Log normalization & parsing
│   ├── rule_engine.py      # YAML rule evaluation logic
│   ├── findings.py         # Finding structure & risk scoring
│   ├── reporter.py         # Multi-format report generation
│   └── theme.py            # Professional UI formatting
├── rules/                  # Detection rule library
│   ├── authentication.yml  # Access control & identity rules
│   ├── network.yml         # Network security monitoring
│   └── system.yml          # System integrity controls
├── config/                 # Configuration management
├── sample_logs/            # Test data for validation
├── scripts/                # Operational utilities
│   └── collect_logs.py     # Secure remote log collection (SSH)
├── tests/                  # Unit test suite
└── output/                 # Generated reports & audit logs
    ├── reports/            # Findings (MD/JSON/CSV)
    └── logs/               # Execution audit trails
