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
Output: Structured findings in output/reports/scan_YYYYMMDD_HHMMSS/ including executive report, machine‑readable JSON, and CSV for analysis.

Command Reference
Core Operations
Command	Purpose	Use Case
scan	Ingest logs, apply detection rules, generate findings	Primary audit execution
report	Regenerate reports from existing JSON findings	Report customization without re‑scanning
list-rules	Display loaded detection rules with metadata	Audit planning and scope validation
Scan Options
bash
python nexus-audit.py scan \
    --log-file PATH          # Single log file
    --log-dir PATH           # Directory of .log/.txt files
    --rules PATH             # YAML rule directory (default: rules/)
    --org "Name"             # Organization for report headers
    --format {markdown,json,csv,all}
    --output-dir PATH        # Custom output location
Architecture
text
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
Detection Rule Library
Rules are declarative YAML configurations defining control objectives, detection logic, and risk parameters.

Rule Structure
yaml
rules:
  - id: "AUTH-001"
    name: "Multiple Failed SSH Login Attempts"
    description: "Detects potential brute force attacks against authentication controls"
    category: "Authentication"
    risk: "High"
    mitre_id: "T1110.001"          # Brute Force: Password Guessing
    mitre_tactic: "Credential Access"
    impact: "Potential account compromise and unauthorized system access"
    recommendation: "Implement account lockout policies; enable multi-factor authentication"
    condition:
      type: threshold
      pattern: "Failed password"
      group_by: source_ip
      count: 5
      window_seconds: 120
Condition Types
Type	Application	Example
pattern_match	Simple control verification	Error keyword detection
regex_match	Complex log format parsing	Structured data extraction
threshold	Anomaly‑based detection	Brute force, DoS patterns
field_value	Specific value validation	Privilege escalation events
Control Coverage
Authentication (AUTH-*)
Brute force detection (AUTH‑001)

Compromise indicators (AUTH‑002)

Invalid user attempts (AUTH‑003)

Privileged access monitoring (AUTH‑004, AUTH‑005)

Account lifecycle events (AUTH‑006)

Network Security (NET-*)
Service availability monitoring (NET‑001)

Reconnaissance detection (NET‑002)

Connection anomaly analysis (NET‑003, NET‑004)

System Integrity (SYS-*)
Scheduled task modification (SYS‑001)

Critical file change detection (SYS‑002)

Service tampering alerts (SYS‑003)

Kernel‑level activity (SYS‑004)

Boot configuration changes (SYS‑005)

Output Formats
After a scan, the tool generates three files in output/reports/scan_YYYYMMDD_HHMMSS/:

Executive Report (audit_report.md)
Risk summary with quantitative breakdowns, control effectiveness assessment, detailed findings with evidence excerpts, and remediation roadmap with priority rankings.

Structured Data (findings.json)
Complete finding metadata, raw evidence preservation, scope and boundary documentation – SIEM integration ready.

Analysis Dataset (findings.csv)
Spreadsheet‑compatible format, pivot‑table ready for trend analysis, risk scoring for heat mapping.

Execution Log (execution_YYYYMMDD_HHMMSS.log)
Complete audit trail of tool operations, quality assurance documentation, chain of custody for evidence handling.

Development
Testing
bash
python3 -m pytest tests/ -v
Adding Custom Rules
Create a .yml file in rules/ or extend existing categories.

Follow the schema: id, name, description, category, risk, mitre_id, condition.

Validate with sample logs.

Rules auto‑load on execution.

Standards Compliance
PEP 8 code style

Type hints for maintainability

Comprehensive docstrings

Audit trail logging throughout

Contributing
Fork the repository.

Create a feature branch: git checkout -b feature/control-enhancement

Add tests for new detection capabilities.

Ensure all tests pass: pytest

Submit a pull request with detailed change description.

Focus Areas: Security control coverage, audit framework alignment, reporting enhancements.

Responsible Use
This tool is provided for educational and authorized professional use only.

Use only on systems and data you are explicitly authorized to analyze.

Comply with all applicable laws, regulations, and organizational policies.

Validate findings through manual review before control decisions.

Test thoroughly in non‑production environments prior to operational deployment.

No warranty provided for accuracy or completeness.

License
MIT License — See LICENSE for details.

Nexus-Audit — Empowering defensible security audits through automated log intelligence.
