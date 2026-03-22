"""
engine/rule_engine.py
=======================
YAML-based detection rule engine.

Every rule lives in a .yml file. No detection logic is hardcoded here --
this module only knows HOW to evaluate conditions; the WHAT is entirely
defined in the YAML files. This makes the engine transparent and auditable:
any auditor can read the rules without reading Python code.

RULE SCHEMA (YAML):
    rules:
      - id: "AUTH-001"
        name: "Multiple Failed Login Attempts"
        description: "Detects brute force or password spraying attacks"
        category: "Authentication"
        risk: "High"
        mitre_id: "T1110.001"
        mitre_tactic: "Credential Access"
        impact: "Account compromise through brute force authentication"
        recommendation: "Implement account lockout after 5 failed attempts.
                         Enable MFA. Review and block offending IP addresses."
        condition:
          type: threshold
          pattern: "Failed password"
          group_by: source_ip
          count: 5
          window_seconds: 60

CONDITION TYPES:
    pattern_match  -- log line contains the string (case-insensitive)
    regex_match    -- log line matches a regex
    threshold      -- pattern seen N+ times in T seconds from same source
    field_value    -- extracted field equals a specified value

USAGE:
    from engine.rule_engine import RuleEngine
    from engine.ingestion   import LogIngester

    engine  = RuleEngine()
    rules   = engine.load_rules("rules/")
    entries = LogIngester().ingest("auth.log")
    matches = engine.evaluate(entries, rules)
"""

import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


# =============================================================================
# RULE DATACLASS
# =============================================================================

@dataclass
class Rule:
    """
    A parsed detection rule loaded from a YAML file.

    Attributes mirror the YAML schema exactly so that any auditor reading
    the YAML file sees the same information as the tool sees internally.
    """
    rule_id:       str
    name:          str
    description:   str
    category:      str
    risk:          str             # Critical | High | Medium | Low | Info
    condition:     dict            # the raw condition dict from YAML
    impact:        str
    recommendation: str
    mitre_id:      str  = ""
    mitre_tactic:  str  = ""
    tags:          list = field(default_factory=list)
    source_file:   str  = ""       # which YAML file this rule came from


# =============================================================================
# RULE MATCH DATACLASS
# =============================================================================

@dataclass
class RuleMatch:
    """
    Records a single rule trigger against a set of log entries.

    A RuleMatch is the intermediate object between raw log entries and
    audit Findings. Multiple RuleMatches for the same rule can be
    consolidated into one Finding.

    Attributes
    ----------
    rule         : Rule       -- the rule that fired
    matched_lines: list[str]  -- the exact log lines that triggered it
    source_file  : str        -- log file where the match was found
    first_seen   : str        -- timestamp of first matching entry
    last_seen    : str        -- timestamp of last matching entry
    source_ip    : str        -- IP address of the actor (if extractable)
    username     : str        -- username involved (if extractable)
    count        : int        -- how many times the pattern matched
    """
    rule:          Rule
    matched_lines: list
    source_file:   str
    first_seen:    str  = ""
    last_seen:     str  = ""
    source_ip:     str  = ""
    username:      str  = ""
    count:         int  = 1


# =============================================================================
# RULE ENGINE
# =============================================================================

class RuleEngine:
    """
    Loads YAML detection rules and evaluates them against log entries.

    Designed for transparency and auditability:
    - Every match can be traced back to the exact log lines that triggered it.
    - Every rule has a human-readable explanation of what it detects and why.
    - The engine never modifies log entries or rule objects.
    """

    def load_rules(self, rules_path: str | Path) -> list[Rule]:
        """
        Load all .yml rule files from a directory (or a single file).

        Parameters
        ----------
        rules_path : str or Path
            A directory containing .yml files, or a single .yml file.

        Returns
        -------
        list[Rule]
            All valid rules loaded in filename order.
            Invalid rules are skipped with a printed warning.

        Raises
        ------
        FileNotFoundError
            If the path does not exist.
        """
        path = Path(rules_path)
        if not path.exists():
            raise FileNotFoundError(f"Rules path not found: {path}")

        # Collect YAML files
        if path.is_dir():
            yml_files = sorted(path.glob("*.yml")) + sorted(path.glob("*.yaml"))
        else:
            yml_files = [path]

        rules = []
        for yml_file in yml_files:
            loaded = self._load_rule_file(yml_file)
            rules.extend(loaded)

        return rules

    def _load_rule_file(self, path: Path) -> list[Rule]:
        """Parse a single YAML rule file and return valid Rule objects."""
        rules = []
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            print(f"  WARNING: Failed to parse rule file '{path.name}': {exc}")
            return []

        if not data or "rules" not in data:
            return []

        for raw_rule in (data.get("rules") or []):
            rule = self._parse_rule(raw_rule, str(path))
            if rule:
                rules.append(rule)

        return rules

    def _parse_rule(self, raw: dict, source_file: str) -> Optional[Rule]:
        """Validate and convert a raw YAML dict to a Rule object."""
        required = ["id", "name", "description", "risk", "condition",  # Required fields for rule validation
                    "impact", "recommendation"]
        for field_name in required:  # Check each required field exists
            if field_name not in raw:
                print(  # Warn about missing fields
                    f"  WARNING: Rule '{raw.get('id', 'UNKNOWN')}' in "
                    f"'{source_file}' missing required field '{field_name}' -- skipped"
                )
                return None

        valid_risks = {"Critical", "High", "Medium", "Low", "Info"}  # Allowed risk levels
        risk = raw["risk"].strip().title()  # Normalize risk to title case
        if risk not in valid_risks:
            print(
                f"  WARNING: Rule '{raw['id']}' has invalid risk "
                f"'{raw['risk']}' -- must be one of {valid_risks}"
            )
            return None

        return Rule(
            rule_id=raw["id"].strip(),
            name=raw["name"].strip(),
            description=raw["description"].strip(),
            category=raw.get("category", "General").strip(),
            risk=risk,
            condition=raw["condition"],
            impact=raw["impact"].strip(),
            recommendation=raw["recommendation"].strip(),
            mitre_id=raw.get("mitre_id", "").strip(),
            mitre_tactic=raw.get("mitre_tactic", "").strip(),
            tags=raw.get("tags", []),
            source_file=source_file,
        )

    # ── Evaluation ────────────────────────────────────────────────────────────

    def evaluate(self, entries: list, rules: list[Rule]) -> list[RuleMatch]:
        """
        Evaluate all rules against all log entries.

        Parameters
        ----------
        entries : list[LogEntry]
            Normalised log entries from LogIngester.
        rules   : list[Rule]
            Loaded detection rules.

        Returns
        -------
        list[RuleMatch]
            All rule matches, sorted by risk severity (Critical first).
        """
    def evaluate(self, entries: list, rules: list[Rule]) -> list[RuleMatch]:
        """
        Evaluate all rules against all log entries.

        Parameters
        ----------
        entries : list[LogEntry]
            Normalised log entries from LogIngester.
        rules   : list[Rule]
            Loaded detection rules.

        Returns
        -------
        list[RuleMatch]
            All rule matches, sorted by risk severity (Critical first).
        """
        all_matches: list[RuleMatch] = []  # Collect all rule matches

        for rule in rules:  # Evaluate each rule
            cond_type = rule.condition.get("type", "pattern_match")  # Get condition type
            try:
                if cond_type == "pattern_match":  # Simple string match
                    matches = self._eval_pattern_match(entries, rule)
                elif cond_type == "regex_match":  # Regular expression match
                    matches = self._eval_regex_match(entries, rule)
                elif cond_type == "threshold":  # Threshold-based detection
                    matches = self._eval_threshold(entries, rule)
                elif cond_type == "field_value":  # Field value comparison
                    matches = self._eval_field_value(entries, rule)
                else:
                    print(f"  WARNING: Unknown condition type '{cond_type}' "  # Warn on unknown type
                          f"in rule '{rule.rule_id}' -- skipped")
                    matches = []
            except Exception as exc:  # Handle evaluation errors
                print(f"  WARNING: Error evaluating rule '{rule.rule_id}': {exc}")
                matches = []

            all_matches.extend(matches)  # Add matches to total list

        # Sort by risk severity
        risk_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}  # Risk priority mapping
        all_matches.sort(key=lambda m: risk_order.get(m.rule.risk, 5))  # Sort matches by risk

        return all_matches  # Return sorted matches

    # ── Condition evaluators ──────────────────────────────────────────────────

    def _eval_pattern_match(
        self,
        entries: list,
        rule:    Rule,
    ) -> list[RuleMatch]:
        """
        Fire when the pattern string appears in any log line.

        Condition YAML:
            type:    pattern_match
            pattern: "Failed password"
        """
        pattern    = rule.condition.get("pattern", "").lower()
        if not pattern:
            return []

        matched = [e for e in entries if pattern in e.raw_line.lower()]
        if not matched:
            return []

        return [RuleMatch(
            rule=rule,
            matched_lines=[e.raw_line for e in matched],
            source_file=matched[0].source_file,
            first_seen=matched[0].timestamp,
            last_seen=matched[-1].timestamp,
            source_ip=self._most_common_ip(matched),
            username=self._most_common_user(matched),
            count=len(matched),
        )]

    def _eval_regex_match(
        self,
        entries: list,
        rule:    Rule,
    ) -> list[RuleMatch]:
        """
        Fire when a regex pattern matches any log line.

        Condition YAML:
            type:    regex_match
            pattern: "sshd\\[\\d+\\]: Failed"
            flags:   IGNORECASE
        """
        raw_pattern = rule.condition.get("pattern", "")
        if not raw_pattern:
            return []

        flags_str = rule.condition.get("flags", "IGNORECASE").upper()
        flags     = re.IGNORECASE if "IGNORECASE" in flags_str else 0

        try:
            compiled = re.compile(raw_pattern, flags)
        except re.error as exc:
            print(f"  WARNING: Invalid regex in rule '{rule.rule_id}': {exc}")
            return []

        matched = [e for e in entries if compiled.search(e.raw_line)]
        if not matched:
            return []

        return [RuleMatch(
            rule=rule,
            matched_lines=[e.raw_line for e in matched],
            source_file=matched[0].source_file,
            first_seen=matched[0].timestamp,
            last_seen=matched[-1].timestamp,
            source_ip=self._most_common_ip(matched),
            username=self._most_common_user(matched),
            count=len(matched),
        )]

    def _eval_threshold(
        self,
        entries: list,
        rule:    Rule,
    ) -> list[RuleMatch]:
        """
        Fire when a pattern appears N+ times from the same source within T seconds.

        Because log timestamps vary in format, this uses line proximity as a
        proxy for time when timestamps cannot be parsed. For accurate time-based
        thresholds, logs must have parseable timestamps.

        Condition YAML:
            type:           threshold
            pattern:        "Failed password"
            group_by:       source_ip     # or username, hostname
            count:          5
            window_seconds: 60
        """
        pattern    = rule.condition.get("pattern", "").lower()
        group_by   = rule.condition.get("group_by", "source_ip")
        threshold  = int(rule.condition.get("count", 5))

        if not pattern:
            return []

        # Filter to matching lines
        matching = [e for e in entries if pattern in e.raw_line.lower()]

        # Group by the specified field
        groups: dict = defaultdict(list)
        for entry in matching:
            key = getattr(entry, group_by, None) or entry.source_ip or "unknown"
            groups[key].append(entry)

        matches = []
        for group_key, group_entries in groups.items():
            if len(group_entries) >= threshold:
                matches.append(RuleMatch(
                    rule=rule,
                    matched_lines=[e.raw_line for e in group_entries[:20]],
                    source_file=group_entries[0].source_file,
                    first_seen=group_entries[0].timestamp,
                    last_seen=group_entries[-1].timestamp,
                    source_ip=(group_entries[0].source_ip
                               if group_by == "source_ip" else self._most_common_ip(group_entries)),
                    username=(group_entries[0].username
                              if group_by == "username" else self._most_common_user(group_entries)),
                    count=len(group_entries),
                ))

        return matches

    def _eval_field_value(
        self,
        entries: list,
        rule:    Rule,
    ) -> list[RuleMatch]:
        """
        Fire when an extracted field matches a specific value.

        Condition YAML:
            type:   field_value
            field:  log_level
            value:  "ERROR"
            pattern: "permission denied"   # optional additional pattern filter
        """
        field_name  = rule.condition.get("field",   "")
        field_value = rule.condition.get("value",   "").lower()
        pattern     = rule.condition.get("pattern", "").lower()

        if not field_name or not field_value:
            return []

        matched = []
        for entry in entries:
            actual = str(getattr(entry, field_name, "")
                         or entry.extra_fields.get(field_name, "")).lower()
            if actual == field_value:
                if pattern and pattern not in entry.raw_line.lower():
                    continue
                matched.append(entry)

        if not matched:
            return []

        return [RuleMatch(
            rule=rule,
            matched_lines=[e.raw_line for e in matched],
            source_file=matched[0].source_file,
            first_seen=matched[0].timestamp,
            last_seen=matched[-1].timestamp,
            source_ip=self._most_common_ip(matched),
            username=self._most_common_user(matched),
            count=len(matched),
        )]

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _most_common_ip(self, entries: list) -> str:
        ips = [e.source_ip for e in entries if e.source_ip]
        if not ips:
            return ""
        return max(set(ips), key=ips.count)

    def _most_common_user(self, entries: list) -> str:
        users = [e.username for e in entries if e.username]
        if not users:
            return ""
        return max(set(users), key=users.count)
