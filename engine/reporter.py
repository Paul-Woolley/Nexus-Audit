"""
engine/reporter.py
====================
Multi-format audit report generator.

Generates three types of output from a list of Finding objects:

    1. MARKDOWN (.md)  -- human-readable, structured as a professional
                          IT audit report. Suitable for submission to
                          audit committees and for inclusion in working papers.

    2. JSON (.json)    -- machine-readable, contains full finding detail.
                          Suitable for SIEM import, ticketing system
                          integration, and pipeline consumption.

    3. CSV (.csv)      -- spreadsheet-compatible. Suitable for Excel-based
                          audit tracking, management review, and remediation
                          tracking worksheets.

REPORT STRUCTURE (Markdown):
    1. Cover Page          -- tool, date, scope summary
    2. Executive Summary   -- risk heatmap table + key statistics
    3. Scope & Objectives  -- what was analysed and why
    4. Methodology         -- how the analysis was conducted
    5. Findings            -- each finding in full, sorted by risk
    6. Conclusion          -- overall risk posture assessment

USAGE:
    from engine.reporter import ReportGenerator

    gen   = ReportGenerator()
    paths = gen.generate(
        findings=findings,
        output_dir="output/reports",
        scope_info={
            "log_files":   ["auth.log", "syslog"],
            "rules_used":  12,
            "lines_processed": 4500,
            "organisation": "Acme Corp",
            "audit_period": "2024-01-15 to 2024-01-15",
        }
    )
    print(paths)   # {"markdown": "...", "json": "...", "csv": "..."}
"""

import csv
import json
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class ReportGenerator:
    """
    Generates Markdown, JSON, and CSV reports from a list of Finding objects.
    """

    # Risk severity order for sorting and display
    _RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

    _RISK_BADGE = {
        "Critical": "**CRITICAL**",
        "High":     "**HIGH**",
        "Medium":   "**MEDIUM**",
        "Low":      "LOW",
        "Info":     "INFO",
    }

    def generate(
        self,
        findings:   list,
        output_dir: str | Path,
        scope_info: Optional[dict] = None,
        formats:    Optional[list] = None,
    ) -> dict[str, str]:
        """
        Generate all configured report formats.

        Parameters
        ----------
        findings   : list[Finding]
            Findings from FindingsGenerator.generate().
        output_dir : str or Path
            Directory to write report files into (created if absent).
            This is typically a timestamped scan directory.
        scope_info : dict, optional
            Metadata about the analysis run. Keys used:
                organisation, audit_period, log_files,
                rules_used, lines_processed
        formats    : list, optional
            Subset of ["markdown", "json", "csv"]. Default: all three.

        Returns
        -------
        dict[str, str]
            {"markdown": "/path/...", "json": "/path/...", "csv": "/path/..."}
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        formats    = formats or ["markdown", "json", "csv"]
        scope_info = scope_info or {}
        ts         = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        paths: dict[str, str] = {}

        if "markdown" in formats:
            md_path  = output_dir / "audit_report.md"
            self._write_markdown(findings, md_path, scope_info, ts)
            paths["markdown"] = str(md_path)

        if "json" in formats:
            json_path = output_dir / "findings.json"
            self._write_json(findings, json_path, scope_info, ts)
            paths["json"] = str(json_path)

        if "csv" in formats:
            csv_path = output_dir / "findings.csv"
            self._write_csv(findings, csv_path)
            paths["csv"] = str(csv_path)

        return paths

    # ── Markdown report ───────────────────────────────────────────────────────

    def _write_markdown(
        self,
        findings:   list,
        path:       Path,
        scope_info: dict,
        ts:         str,
    ) -> None:
        """Write a professionally structured Markdown audit report."""

        org         = scope_info.get("organisation", "N/A")
        period      = scope_info.get("audit_period", "See report date")
        log_files   = scope_info.get("log_files", [])
        rules_used  = scope_info.get("rules_used", "N/A")
        lines_proc  = scope_info.get("lines_processed", "N/A")
        report_date = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")

        # Summary counts
        total       = len(findings)
        by_risk     = {r: 0 for r in self._RISK_ORDER}
        for f in findings:
            by_risk[f.risk] = by_risk.get(f.risk, 0) + 1

        overall_risk = self._compute_overall_risk(by_risk)

        lines = []

        # ── Cover ──────────────────────────────────────────────────────────
        lines += [
            "# IT Security Audit Report",
            "",
            "---",
            "",
            f"| Field              | Value                        |",
            f"|:-------------------|:-----------------------------|",
            f"| **Organisation**   | {org}                        |",
            f"| **Audit Period**   | {period}                     |",
            f"| **Report Date**    | {report_date}                |",
            f"| **Prepared By**    | Nexus Audit Tool v1.0        |",
            f"| **Overall Risk**   | {self._RISK_BADGE[overall_risk]} |",
            f"| **Total Findings** | {total}                      |",
            "",
            "---",
            "",
        ]

        # ── Executive Summary ──────────────────────────────────────────────
        lines += [
            "## 1. Executive Summary",
            "",
            self._executive_summary_text(by_risk, overall_risk, total, org),
            "",
            "### 1.1 Risk Summary",
            "",
            "| Risk Level   | Findings |",
            "|:-------------|:--------:|",
        ]
        for risk in ["Critical", "High", "Medium", "Low", "Info"]:
            count = by_risk.get(risk, 0)
            badge = self._RISK_BADGE[risk]
            lines.append(f"| {badge:<12} | {count:^8} |")
        lines += ["", "---", ""]

        # ── Scope & Objectives ─────────────────────────────────────────────
        lines += [
            "## 2. Scope & Objectives",
            "",
            "### 2.1 Objectives",
            "",
            "This assessment was conducted to:",
            "",
            "- Identify security control gaps and anomalous activity in system logs",
            "- Provide evidence-based findings aligned with industry control frameworks",
            "- Generate actionable recommendations to strengthen the control environment",
            "- Support internal audit and IT assurance activities",
            "",
            "### 2.2 Scope",
            "",
            f"**Log files analysed:** {len(log_files)}",
            "",
        ]
        for lf in log_files:
            lines.append(f"- `{lf}`")
        if not log_files:
            lines.append("- *(no log files specified)*")

        lines += [
            "",
            f"**Detection rules applied:** {rules_used}",
            f"**Log lines processed:**      {lines_proc:,}" if isinstance(lines_proc, int) else f"**Log lines processed:** {lines_proc}",
            "",
            "### 2.3 Out of Scope",
            "",
            "- Physical security controls",
            "- Network infrastructure configuration review",
            "- Application source code review",
            "- Controls not observable from log data",
            "",
            "---",
            "",
        ]

        # ── Methodology ────────────────────────────────────────────────────
        lines += [
            "## 3. Methodology",
            "",
            "The assessment followed a structured three-phase approach:",
            "",
            "**Phase 1 – Log Ingestion**",
            "Log files were ingested and normalised into a structured format. "
            "Each log line was parsed to extract key fields including timestamp, "
            "hostname, service, source IP address, and username where present. "
            "Lines that could not be fully parsed were still retained for "
            "pattern-matching purposes.",
            "",
            "**Phase 2 – Rule-Based Detection**",
            "Normalised log entries were evaluated against a library of YAML-defined "
            "detection rules. Each rule specifies a condition type, pattern, risk level, "
            "MITRE ATT&CK mapping, impact statement, and remediation recommendation. "
            "Four condition types are supported: `pattern_match`, `regex_match`, "
            "`threshold` (N occurrences within a time window), and `field_value` "
            "(specific field equals a value). All rule logic is human-readable and "
            "independently verifiable.",
            "",
            "**Phase 3 – Findings Generation**",
            "Each triggered rule produced one or more findings. Findings were "
            "enriched with evidence (log line excerpts), context (source IP, username, "
            "occurrence count), and a structured recommendation. Findings were "
            "prioritised by risk level in accordance with standard audit practice.",
            "",
            "---",
            "",
        ]

        # ── Findings ───────────────────────────────────────────────────────
        lines += [
            "## 4. Findings",
            "",
        ]

        if not findings:
            lines += [
                "> **No findings were identified.** All detection rules evaluated "
                "against the provided log files produced no matches. This may "
                "indicate effective controls, limited log coverage, or insufficient "
                "rule coverage for the environment.",
                "",
            ]
        else:
            for finding in sorted(
                findings,
                key=lambda f: self._RISK_ORDER.get(f.risk, 5)
            ):
                lines += self._finding_to_markdown(finding)

        lines += ["---", ""]

        # ── Conclusion ─────────────────────────────────────────────────────
        lines += [
            "## 5. Conclusion",
            "",
            self._conclusion_text(by_risk, overall_risk, org),
            "",
            "### 5.1 Recommended Priority Actions",
            "",
        ]

        # List High/Critical recommendations
        priority_findings = [
            f for f in findings if f.risk in ("Critical", "High")
        ]
        if priority_findings:
            for f in priority_findings:
                lines.append(
                    f"1. **[{f.finding_id}] {f.title}** -- {f.recommendation[:120]}..."
                )
        else:
            lines.append("No Critical or High findings identified. Continue monitoring.")

        lines += [
            "",
            "---",
            "",
            "*This report was generated automatically by Nexus Audit Tool v1.0. "
            "All findings should be reviewed and validated by a qualified IT audit "
            "professional before submission or remediation action.*",
            "",
        ]

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def _finding_to_markdown(self, finding) -> list[str]:
        """Format a single Finding as Markdown."""
        lines = []
        risk_badge = self._RISK_BADGE[finding.risk]
        mitre_ref  = (
            f"[{finding.mitre_id}](https://attack.mitre.org/techniques/"
            f"{finding.mitre_id.replace('.', '/')}/)"
            if finding.mitre_id else "N/A"
        )

        lines += [
            f"### {finding.finding_id}: {finding.title}",
            "",
            f"| Attribute         | Value                                |",
            f"|:------------------|:-------------------------------------|",
            f"| **Finding ID**    | `{finding.finding_id}`              |",
            f"| **Rule ID**       | `{finding.rule_id}`                 |",
            f"| **Risk Level**    | {risk_badge}                        |",
            f"| **Category**      | {finding.category}                  |",
            f"| **Source File**   | `{finding.source_file}`             |",
            f"| **Occurrences**   | {finding.occurrence_count}          |",
            f"| **First Seen**    | {finding.first_seen}                |",
            f"| **Last Seen**     | {finding.last_seen}                 |",
            f"| **Source IP**     | {finding.source_ip or 'N/A'}        |",
            f"| **Account**       | {finding.username or 'N/A'}         |",
            f"| **MITRE ATT&CK**  | {mitre_ref}                         |",
            f"| **Tactic**        | {finding.mitre_tactic or 'N/A'}     |",
            "",
            "**Description**",
            "",
            finding.description,
            "",
            "**Evidence**",
            "",
            "```",
        ]
        for line in finding.evidence[:5]:
            lines.append(line)
        lines += [
            "```",
            "",
            "**Impact**",
            "",
            finding.impact,
            "",
            "**Recommendation**",
            "",
            finding.recommendation,
            "",
            "---",
            "",
        ]
        return lines

    def _executive_summary_text(
        self,
        by_risk:      dict,
        overall_risk: str,
        total:        int,
        org:          str,
    ) -> str:
        critical = by_risk.get("Critical", 0)
        high     = by_risk.get("High",     0)
        medium   = by_risk.get("Medium",   0)
        low      = by_risk.get("Low",      0)

        if total == 0:
            return (
                f"No security findings were identified during this assessment of "
                f"{org}. All detection rules evaluated against the provided log "
                f"files produced no matches."
            )

        risk_statement = {
            "Critical": "requires immediate remediation action",
            "High":     "requires prompt attention and remediation",
            "Medium":   "requires management review and planned remediation",
            "Low":      "represents minor control improvements",
        }.get(overall_risk, "requires management review")

        parts = []
        if critical:
            parts.append(f"{critical} Critical finding{'s' if critical > 1 else ''}")
        if high:
            parts.append(f"{high} High finding{'s' if high > 1 else ''}")
        if medium:
            parts.append(f"{medium} Medium finding{'s' if medium > 1 else ''}")
        if low:
            parts.append(f"{low} Low finding{'s' if low > 1 else ''}")

        findings_summary = ", ".join(parts) if parts else f"{total} findings"

        return (
            f"This assessment of {org} identified **{total} security finding{'s' if total > 1 else ''}** "
            f"across the analysed log files: {findings_summary}. "
            f"The overall risk posture is assessed as **{overall_risk}**, which "
            f"{risk_statement}. "
            f"Detailed findings, evidence, and recommendations are provided in Section 4."
        )

    def _conclusion_text(
        self,
        by_risk:      dict,
        overall_risk: str,
        org:          str,
    ) -> str:
        total    = sum(by_risk.values())
        critical = by_risk.get("Critical", 0)
        high     = by_risk.get("High",     0)

        if total == 0:
            return (
                f"No security findings were identified in the log data reviewed for {org}. "
                f"The detection rules applied did not identify any anomalous or potentially "
                f"malicious activity. Management should ensure ongoing log monitoring and "
                f"periodic reassessment as the threat landscape evolves."
            )

        urgency = ""
        if critical:
            urgency = (
                f"Immediate action is required to address {critical} Critical finding"
                f"{'s' if critical > 1 else ''}."
            )
        elif high:
            urgency = (
                f"Prompt action is recommended to address {high} High finding"
                f"{'s' if high > 1 else ''}."
            )

        return (
            f"The log analysis for {org} identified {total} finding{'s' if total > 1 else ''} "
            f"representing a **{overall_risk}** overall risk to the organisation's information "
            f"security posture. {urgency} "
            f"Management is encouraged to review all findings, assess the applicability of "
            f"each recommendation to their specific environment, and establish a remediation "
            f"plan with assigned ownership and target completion dates. "
            f"A follow-up assessment is recommended after remediation actions have been "
            f"implemented to verify control effectiveness."
        )

    def _compute_overall_risk(self, by_risk: dict) -> str:
        for risk in ["Critical", "High", "Medium", "Low", "Info"]:
            if by_risk.get(risk, 0) > 0:
                return risk
        return "Info"

    # ── JSON report ───────────────────────────────────────────────────────────

    def _write_json(
        self,
        findings:   list,
        path:       Path,
        scope_info: dict,
        ts:         str,
    ) -> None:
        """Write a machine-readable JSON findings file."""
        from dataclasses import asdict

        by_risk = {r: 0 for r in self._RISK_ORDER}
        for f in findings:
            by_risk[f.risk] = by_risk.get(f.risk, 0) + 1

        data = {
            "report_metadata": {
                "generated_at":      datetime.now(timezone.utc).isoformat(),
                "tool":              "Nexus Audit Tool v1.0",
                "organisation":      scope_info.get("organisation", "N/A"),
                "audit_period":      scope_info.get("audit_period", "N/A"),
                "log_files":         scope_info.get("log_files", []),
                "rules_applied":     scope_info.get("rules_used", 0),
                "lines_processed":   scope_info.get("lines_processed", 0),
                "total_findings":    len(findings),
                "overall_risk":      self._compute_overall_risk(by_risk),
                "risk_summary":      by_risk,
            },
            "findings": [
                {
                    "finding_id":       f.finding_id,
                    "rule_id":          f.rule_id,
                    "rule_name":        f.rule_name,
                    "title":            f.title,
                    "risk":             f.risk,
                    "category":         f.category,
                    "description":      f.description,
                    "evidence":         f.evidence,
                    "impact":           f.impact,
                    "recommendation":   f.recommendation,
                    "source_file":      f.source_file,
                    "first_seen":       f.first_seen,
                    "last_seen":        f.last_seen,
                    "source_ip":        f.source_ip,
                    "username":         f.username,
                    "occurrence_count": f.occurrence_count,
                    "mitre_id":         f.mitre_id,
                    "mitre_tactic":     f.mitre_tactic,
                    "generated_at":     f.generated_at,
                }
                for f in findings
            ],
        }

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)

    # ── CSV report ────────────────────────────────────────────────────────────

    def _write_csv(self, findings: list, path: Path) -> None:
        """
        Write a CSV findings file for Excel and audit workflow tools.

        Columns are ordered for readability in a spreadsheet context,
        with remediation columns positioned last for tracking purposes.
        """
        fieldnames = [
            "Finding ID", "Risk Level", "Category", "Title",
            "Rule ID", "Description", "Source File", "First Seen",
            "Last Seen", "Source IP", "Account", "Occurrences",
            "MITRE ID", "MITRE Tactic", "Impact", "Recommendation",
            "Evidence (First Line)", "Generated At",
        ]

        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for f in findings:
                writer.writerow({
                    "Finding ID":           f.finding_id,
                    "Risk Level":           f.risk,
                    "Category":             f.category,
                    "Title":                f.title,
                    "Rule ID":              f.rule_id,
                    "Description":          f.description,
                    "Source File":          f.source_file,
                    "First Seen":           f.first_seen,
                    "Last Seen":            f.last_seen,
                    "Source IP":            f.source_ip,
                    "Account":              f.username,
                    "Occurrences":          f.occurrence_count,
                    "MITRE ID":             f.mitre_id,
                    "MITRE Tactic":         f.mitre_tactic,
                    "Impact":               f.impact,
                    "Recommendation":       f.recommendation,
                    "Evidence (First Line)": f.evidence[0] if f.evidence else "",
                    "Generated At":         f.generated_at,
                })
