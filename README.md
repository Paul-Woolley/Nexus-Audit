**Nexus-Audit**  
**Security Log Analysis & IT Audit Reporting Framework**  
*Transforming raw log data into defensible, risk-rated audit intelligence aligned with industry control frameworks*  
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OQQmAABRAsSdYxZ4/mJjEsxE8W8GbCFuCLTOzVXsAAPzFuVZ3dXw9AQDgtesBxPEF3bv7x0IAAAAASUVORK5CYII=)  
**Overview**  
**Nexus-Audit** is a modular, CLI-based security auditing system engineered for  **IT auditors, risk professionals, and security teams**. It bridges the gap between technical log analysis and executive-ready audit reporting by:  
- **Automating** the detection of security control failures across authentication, network, and system integrity domains  
- **Standardizing** findings against MITRE ATT&CK tactics and IIA audit standards  
- **Delivering** multi-format outputs (Markdown, JSON, CSV) for diverse stakeholder communication  
- **Ensuring** complete audit trail documentation for regulatory defensibility  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OQQmAABRAsSdYxKY/jMFMIZ7ECt5E2BJsmZmt2gMA4C+Otbqr8+sJAACvXQ85QgYXd/O+eQAAAABJRU5ErkJggg==)  
**Key Capabilities**  
| | |  
|-|-|  
| **Feature** | **Business Value** |   
| **Multi-Format Log Ingestion** | Syslog, Apache, ISO 8601, and generic text parsing eliminates manual data normalization |   
| **Declarative YAML Rule Engine** | Audit logic codified as version-controlled rules—enabling repeatable, defensible assessments |   
| **Risk-Based Prioritization** | Automated severity scoring with MITRE ATT&CK mapping for threat-informed risk response |   
| **Audit-Ready Reporting** | Executive summaries, detailed findings with evidence, and remediation guidance |   
| **Complete Audit Trail** | Execution logging ensures tool accountability and supports quality assurance reviews |   
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OsQ1AABRAwSdRaPXGMOCv7WkPK+hEcjfBLTNzVFcAAPzFvVZbdX49AQDgtf0BSpoDXv5TGXgAAAAASUVORK5CYII=)  
**Quick Start**  
# 1. Clone repository  
 git clone https://github.com/yourusername/nexus-audit.git  
 cd nexus-audit  
   
 # 2. Create virtual environment  
 python3 -m venv venv && source venv/bin/activate  
   
 # 3. Install dependencies  
 pip install -r requirements.txt  
   
 # 4. Execute baseline audit scan  
 python nexus-audit.py scan \  
     --log-file sample_logs/auth.log \  
     --rules rules/ \  
     --org "Your Organization" \  
     --format all  
   
**Output:** Structured findings in output/reports/scan_YYYYMMDD_HHMMSS/ including executive report, machine-readable JSON, and CSV for analysis.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OMQ2AABAAsSNBCkLfFDZwwIgHRiywEZJWQZeZ2ao9AAD+4lyruzq+ngAA8Nr1AOH0BedHjjlfAAAAAElFTkSuQmCC)  
**Command Reference**  
**Core Operations**  
| | | |  
|-|-|-|  
| **Command** | **Purpose** | **Use Case** |   
| scan | Ingest logs, apply detection rules, generate findings | Primary audit execution |   
| report | Regenerate reports from existing JSON findings | Report customization without re-scanning |   
| list-rules | Display loaded detection rules with metadata | Audit planning and scope validation |   
   
**Scan Options**  
python nexus-audit.py scan \  
     --log-file PATH \          # Single log file  
     --log-dir PATH \           # Directory of .log/.txt files  
     --rules PATH \             # YAML rule directory (default: rules/)  
     --org "Name" \             # Organization for report headers  
     --format {markdown,json,csv,all} \  
     --output-dir PATH          # Custom output location  
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OQQmAABRAsSd4EKxgBjP+Asa0hxW8ibAl2DIzR3UFAMBf3Gu1VefXEwAAXtsfSqwDVbgKngwAAAAASUVORK5CYII=)  
**Architecture**  
nexus-audit/  
 ├── nexus-audit.py          # CLI entry point  
 ├── engine/                 # Core audit engine  
 │   ├── ingestion.py        # Log normalization & parsing  
 │   ├── rule_engine.py      # YAML rule evaluation logic  
 │   ├── findings.py         # Finding structure & risk scoring  
 │   ├── reporter.py         # Multi-format report generation  
 │   └── theme.py            # Professional UI formatting  
 ├── rules/                  # Detection rule library  
 │   ├── authentication.yml  # Access control & identity rules  
 │   ├── network.yml         # Network security monitoring  
 │   └── system.yml          # System integrity controls  
 ├── config/                 # Configuration management  
 ├── sample_logs/            # Test data for validation  
 ├── scripts/                # Operational utilities  
 │   └── collect_logs.py     # Secure remote log collection (SSH)  
 ├── tests/                  # Unit test suite  
 └── output/                 # Generated reports & audit logs  
     ├── reports/            # Findings (MD/JSON/CSV)  
     └── logs/               # Execution audit trails  
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OMQ2AABAAsSNBCkLfFDZwwIgHRiywEZJWQZeZ2ao9AAD+4lyruzq+ngAA8Nr1AOH0BedHjjlfAAAAAElFTkSuQmCC)  
**Detection Rule Library**  
Rules are declarative YAML configurations defining **control objectives, detection logic, and risk parameters**.  
**Rule Structure**  
rules:  
   - id: "AUTH-001"  
     name: "Multiple Failed SSH Login Attempts"  
     description: "Detects potential brute force attacks against authentication controls"  
     category: "Authentication"  
     risk: "High"  
     mitre_id: "T1110.001"          # Brute Force: Password Guessing  
     mitre_tactic: "Credential Access"  
     impact: "Potential account compromise and unauthorized system access"  
     recommendation: "Implement account lockout policies; enable multi-factor authentication"  
     condition:  
       type: threshold  
       pattern: "Failed password"  
       group_by: source_ip  
       count: 5  
       window_seconds: 120  
   
**Condition Types**  
| | | |  
|-|-|-|  
| **Type** | **Application** | **Example** |   
| pattern_match | Simple control verification | Error keyword detection |   
| regex_match | Complex log format parsing | Structured data extraction |   
| threshold | Anomaly-based detection | Brute force, DoS patterns |   
| field_value | Specific value validation | Privilege escalation events |   
   
**Control Coverage**  
**Authentication (AUTH-*)**  
- Brute force detection (AUTH-001)  
- Compromise indicators (AUTH-002)  
- Invalid user attempts (AUTH-003)  
- Privileged access monitoring (AUTH-004, AUTH-005)  
- Account lifecycle events (AUTH-006)  
**Network Security (NET-*)**  
- Service availability monitoring (NET-001)  
- Reconnaissance detection (NET-002)  
- Connection anomaly analysis (NET-003, NET-004)  
**System Integrity (SYS-*)**  
- Scheduled task modification (SYS-001)  
- Critical file change detection (SYS-002)  
- Service tampering alerts (SYS-003)  
- Kernel-level activity (SYS-004)  
- Boot configuration changes (SYS-005)  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAM0lEQVR4nO3OMQ0AIAwAwdIgBKl1gjacsGCAiZDcTT9+q6oRETMAAPjF6ify6QYAADdyA9Y0AypN+bdfAAAAAElFTkSuQmCC)  
**Output Formats**  
**Executive Report (**audit_report.md **)**  
- Risk summary with quantitative breakdowns  
- Control effectiveness assessment  
- Detailed findings with evidence excerpts  
- Remediation roadmap with priority rankings  
**Structured Data (**findings.json **)**  
- Complete finding metadata  
- Raw evidence preservation  
- Scope and boundary documentation  
- SIEM integration ready  
**Analysis Dataset (**findings.csv **)**  
- Spreadsheet-compatible format  
- Pivot-table ready for trend analysis  
- Risk scoring for heat mapping  
**Execution Log (**execution_YYYYMMDD_HHMMSS.log **)**  
- Complete audit trail of tool operations  
- Quality assurance documentation  
- Chain of custody for evidence handling  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OQQmAABRAsSdYxZ4/mJjEsxE8W8GbCFuCLTOzVXsAAPzFuVZ3dXw9AQDgtesBxPEF3bv7x0IAAAAASUVORK5CYII=)  
**Development**  
**Testing**  
python3 -m pytest tests/ -v  
   
**Adding Custom Rules**  
1. Create .yml file in rules/ or extend existing categories  
2. Follow schema: id, name, description, category, risk, mitre_id, condition  
3. Validate with sample logs  
4. Rules auto-load on execution  
**Standards Compliance**  
- **PEP 8** code style  
- Type hints for maintainability  
- Comprehensive docstrings  
- Audit trail logging throughout  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OQQmAUBBAwSfIb+HdmNvAkgaxgjcRZhLMNjNHdQUAwF/ce7Wq8+sJAACvrQctewNKtdojwQAAAABJRU5ErkJggg==)  
**Contributing**  
1. Fork repository  
2. Create feature branch: git checkout -b feature/control-enhancement  
3. Add tests for new detection capabilities  
4. Ensure all tests pass: pytest  
5. Submit pull request with detailed change description  
**Focus Areas:** Security control coverage, audit framework alignment, reporting enhancements.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OMQ2AABAAsSNBACPiUML0NpGACyywEZJWQZeZ2aszAAD+4l6rrTq+ngAA8Nr1AL/SBEZwuCSwAAAAAElFTkSuQmCC)  
**Responsible Use**  
**This tool is provided for educational and authorized professional use only.**  
- Use only on systems and data you are **explicitly authorized** to analyze  
- Comply with all applicable laws, regulations, and organizational policies  
- Validate findings through manual review before control decisions  
- Test thoroughly in non-production environments prior to operational deployment  
- No warranty provided for accuracy or completeness  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OMQ2AABAAsSPBCj5fFgpQwYwEZiywEZJWQZeZ2ao9AAD+4lyruzq+ngAA8Nr1AMTRBeEgNK9YAAAAAElFTkSuQmCC)  
**License**  
MIT License — See [LICENSE for details.](LICENSE "LICENSE")  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OQQmAABRAsSeYxKS/kJkED6bwYAVvImwJtszMVu0BAPAXx1rd1fn1BACA164HHDwF+DpPyKwAAAAASUVORK5CYII=)  
   *Nexus-Audit — Empowering defensible security audits through automated log intelligence.*  
   
