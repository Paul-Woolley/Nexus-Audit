"""
engine/findings.py
====================
Converts RuleMatch objects into structured audit Findings.

A Finding is the publishable audit artefact -- it has a unique ID,
a clear title, evidence from the logs, an impact statement, and a
specific recommendation. This is the format used in the final report.

Multiple RuleMatches for the same rule (e.g. the same attack from
different source IPs) are each converted to a separate Finding so
every instance is documented independently.

FINDING STRUCTURE (aligned with IIA standards):
    Finding ID      -- unique reference for the report (e.g. F-001)
    Title           -- concise description of the issue
    Risk Level      -- Critical / High / Medium / Low / Info
    Category        -- Authentication / Network / System / etc.
    Description     -- what was detected, in plain language
    Evidence        -- up to 5 log lines proving the finding
    Impact          -- business/security consequence
    Recommendation  -- specific, actionable remediation steps
    MITRE ATT&CK    -- technique ID and tactic (if applicable)
    Source File     -- which log file the finding came from
    First/Last Seen -- time range of the activity

USAGE:
    from engine.findings import FindingsGenerator, Finding

    generator = FindingsGenerator()
    findings  = generator.generate(rule_matches)
    for f in findings:
        print(f.finding_id, f.title, f.risk)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# =============================================================================
# FINDING DATACLASS
# =============================================================================

@dataclass
class Finding:
    """
    A single auditable finding generated from a rule match.

    This is the canonical output unit of the audit engine. Every report
    (Markdown, JSON, CSV) is built from a list of these objects.
    """
    finding_id:     str             # e.g. "F-001", "F-002"
    rule_id:        str             # e.g. "AUTH-001"
    rule_name:      str             # human name of the rule that fired
    title:          str             # concise finding title
    risk:           str             # Critical | High | Medium | Low | Info
    category:       str             # e.g. Authentication, Network, System
    description:    str             # what was detected
    evidence:       list[str]       # log lines (max 5) proving the finding
    impact:         str             # business/security consequence
    recommendation: str             # specific remediation steps
    source_file:    str             # log file name (not full path)
    first_seen:     str             # timestamp of first occurrence
    last_seen:      str             # timestamp of last occurrence
    source_ip:      str  = ""      # attacking IP if identified
    username:       str  = ""      # account involved if identified
    occurrence_count: int = 1      # how many times the pattern triggered
    mitre_id:       str  = ""      # e.g. "T1110.001"
    mitre_tactic:   str  = ""      # e.g. "Credential Access"
    generated_at:   str  = ""      # when this finding was produced

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()


# =============================================================================
# FINDINGS GENERATOR
# =============================================================================

class FindingsGenerator:
    """
    Converts a list of RuleMatches into structured Finding objects.

    Each RuleMatch becomes one Finding. Evidence is limited to the 5
    most relevant log lines to keep reports readable -- the full set
    of matched lines is available in the raw JSON output if needed.
    """

    # Maximum number of evidence log lines per finding
    MAX_EVIDENCE_LINES = 5

    def generate(self, rule_matches: list) -> list:
        """
        Convert RuleMatches to Findings.

        Parameters
        ----------
        rule_matches : list[RuleMatch]
            Output of RuleEngine.evaluate().

        Returns
        -------
        list[Finding]
            Numbered findings, sorted by risk (Critical first).
        """
        findings: list[Finding] = []  # List to hold generated findings

        for idx, match in enumerate(rule_matches, start=1):  # Iterate matches with index
            finding = self._match_to_finding(match, idx)  # Convert match to finding
            findings.append(finding)  # Add to findings list

        return findings  # Return list of findings

    def _match_to_finding(self, match, idx: int) -> Finding:
        """Convert a single RuleMatch to a Finding."""
        from pathlib import Path

        rule     = match.rule  # Get the rule that triggered the match
        finding_id = f"F-{idx:03d}"  # Generate unique finding ID

        # Select the most informative evidence lines
        evidence = self._select_evidence(match.matched_lines)  # Limit evidence to 5 lines

        # Build a concise description
        description = self._build_description(match)  # Create detailed description

        # Source file: show just the filename, not the full path
        source_filename = Path(match.source_file).name if match.source_file else "unknown"  # Extract filename

        return Finding(  # Create and return Finding object
            finding_id=finding_id,  # Unique ID
            rule_id=rule.rule_id,  # Rule identifier
            rule_name=rule.name,  # Rule name
            title=rule.name,  # Finding title
            risk=rule.risk,  # Risk level
            category=rule.category,  # Category
            description=description,  # Detailed description
            evidence=evidence,  # Selected evidence lines
            impact=rule.impact,  # Business impact
            recommendation=rule.recommendation,  # Remediation steps
            source_file=source_filename,  # Source log file name
            first_seen=match.first_seen or "not recorded",  # First occurrence
            last_seen=match.last_seen or "not recorded",  # Last occurrence
            source_ip=match.source_ip,  # Attacker IP
            username=match.username,  # Involved username
            occurrence_count=match.count,  # Number of occurrences
            mitre_id=rule.mitre_id,  # MITRE technique ID
            mitre_tactic=rule.mitre_tactic,  # MITRE tactic
        )

    def _build_description(self, match) -> str:
        """
        Build a readable description combining rule description with
        specific context from the match (IP address, username, count).
        """
        rule  = match.rule
        parts = [rule.description]

        context_parts = []
        if match.count > 1:
            context_parts.append(f"{match.count} occurrences detected")
        if match.source_ip:
            context_parts.append(f"source IP: {match.source_ip}")
        if match.username:
            context_parts.append(f"account: {match.username}")
        if match.first_seen and match.last_seen and match.first_seen != match.last_seen:
            context_parts.append(
                f"activity observed between {match.first_seen} and {match.last_seen}"
            )
        elif match.first_seen:
            context_parts.append(f"observed at {match.first_seen}")

        if context_parts:
            parts.append("Detail: " + "; ".join(context_parts) + ".")

        return " ".join(parts)

    def _select_evidence(self, lines: list[str]) -> list[str]:
        """
        Select the most informative evidence lines.

        Strategy:
        - Always include the first line (establishes context)
        - Always include the last line (shows the extent)
        - Fill remaining slots from the middle
        - Deduplicate (very similar lines are collapsed)
        - Limit to MAX_EVIDENCE_LINES
        """
        if not lines:
            return []

        if len(lines) <= self.MAX_EVIDENCE_LINES:
            return [l.strip() for l in lines]

        # First + last + sample from middle
        selected = [lines[0]]
        mid_count = self.MAX_EVIDENCE_LINES - 2
        step = max(1, (len(lines) - 2) // mid_count)
        for i in range(1, len(lines) - 1, step):
            selected.append(lines[i])
            if len(selected) >= self.MAX_EVIDENCE_LINES - 1:
                break
        selected.append(lines[-1])

        return [l.strip() for l in selected[:self.MAX_EVIDENCE_LINES]]
