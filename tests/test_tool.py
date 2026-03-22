"""
tests/test_tool.py
====================
Full test suite for Nexus Audit Tool.

Tests every component in isolation (unit) and end-to-end (integration).
Run with: python -m pytest tests/ -v

All tests are self-contained -- they create their own temp files and
clean up after themselves. No persistent state. No internet required.
"""

import csv
import json
import sys
from pathlib import Path

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def tmp_dir(tmp_path):
    return tmp_path

@pytest.fixture
def sample_auth_log(tmp_path):
    """Write a minimal but realistic auth.log for testing."""
    content = """Jan 15 09:00:01 host sshd[1001]: Failed password for root from 192.168.1.105 port 50001 ssh2
Jan 15 09:00:03 host sshd[1002]: Failed password for root from 192.168.1.105 port 50002 ssh2
Jan 15 09:00:05 host sshd[1003]: Failed password for admin from 192.168.1.105 port 50003 ssh2
Jan 15 09:00:07 host sshd[1004]: Invalid user test from 192.168.1.105 port 50004
Jan 15 09:00:09 host sshd[1005]: Failed password for root from 192.168.1.105 port 50005 ssh2
Jan 15 09:00:11 host sshd[1006]: Failed password for root from 192.168.1.105 port 50006 ssh2
Jan 15 09:00:45 host sshd[1050]: Accepted password for root from 192.168.1.105 port 50050 ssh2
Jan 15 09:05:00 host sudo:    root : TTY=pts/1 ; USER=root ; COMMAND=/bin/bash
Jan 15 09:06:00 host useradd[2001]: new user: name=backdoor, UID=1001
"""
    path = tmp_path / "auth.log"
    path.write_text(content)
    return path

@pytest.fixture
def sample_syslog(tmp_path):
    content = """Jan 15 09:01:00 host CRON[2200]: (root) CMD (/bin/bash /tmp/.script.sh)
Jan 15 09:09:00 host systemd[1]: systemctl stop rsyslog
Jan 15 09:10:00 host kernel: [12345.6] general protection fault: 0000 [#1] SMP
Jan 15 09:10:01 host kernel: [12345.7] Call Trace:
"""
    path = tmp_path / "syslog.log"
    path.write_text(content)
    return path

@pytest.fixture
def rules_dir(tmp_path):
    """Create a minimal rules directory with test rules."""
    rules_d = tmp_path / "rules"
    rules_d.mkdir()
    (rules_d / "test_rules.yml").write_text("""
rules:
  - id: "TEST-001"
    name: "Test Failed Login"
    description: "Detects failed SSH logins"
    category: "Authentication"
    risk: "High"
    mitre_id: "T1110.001"
    mitre_tactic: "Credential Access"
    impact: "Account compromise"
    recommendation: "Implement account lockout"
    condition:
      type: pattern_match
      pattern: "Failed password"

  - id: "TEST-002"
    name: "Test Successful Login"
    description: "Detects successful SSH logins"
    category: "Authentication"
    risk: "Critical"
    mitre_id: "T1110.001"
    mitre_tactic: "Credential Access"
    impact: "Possible compromise"
    recommendation: "Investigate immediately"
    condition:
      type: pattern_match
      pattern: "Accepted password"

  - id: "TEST-003"
    name: "Test Threshold Rule"
    description: "Detects brute force via threshold"
    category: "Authentication"
    risk: "High"
    mitre_id: "T1110.001"
    mitre_tactic: "Credential Access"
    impact: "Brute force attack"
    recommendation: "Block source IP"
    condition:
      type: threshold
      pattern: "Failed password"
      group_by: source_ip
      count: 3
      window_seconds: 60

  - id: "TEST-004"
    name: "Test Regex Rule"
    description: "Detects user creation via regex"
    category: "Authentication"
    risk: "High"
    mitre_id: "T1136.001"
    mitre_tactic: "Persistence"
    impact: "Unauthorised account"
    recommendation: "Remove account"
    condition:
      type: regex_match
      pattern: "useradd|new user"
      flags: IGNORECASE
""")
    return rules_d


# =============================================================================
# INGESTION TESTS
# =============================================================================

class TestLogIngester:

    def test_ingest_valid_log_returns_entries(self, sample_auth_log):
        from engine.ingestion import LogIngester
        entries = LogIngester().ingest(sample_auth_log)
        assert len(entries) > 0

    def test_ingest_extracts_source_ip(self, sample_auth_log):
        from engine.ingestion import LogIngester
        entries = LogIngester().ingest(sample_auth_log)
        ips = [e.source_ip for e in entries if e.source_ip]
        assert "192.168.1.105" in ips

    def test_ingest_extracts_username(self, sample_auth_log):
        from engine.ingestion import LogIngester
        entries = LogIngester().ingest(sample_auth_log)
        users = [e.username for e in entries if e.username]
        assert len(users) > 0

    def test_ingest_extracts_service(self, sample_auth_log):
        from engine.ingestion import LogIngester
        entries = LogIngester().ingest(sample_auth_log)
        services = [e.service for e in entries if e.service]
        assert "sshd" in services

    def test_ingest_preserves_raw_line(self, sample_auth_log):
        from engine.ingestion import LogIngester
        entries = LogIngester().ingest(sample_auth_log)
        assert all(e.raw_line for e in entries)

    def test_ingest_sets_line_number(self, sample_auth_log):
        from engine.ingestion import LogIngester
        entries = LogIngester().ingest(sample_auth_log)
        line_numbers = [e.line_number for e in entries]
        assert 1 in line_numbers
        assert line_numbers == sorted(line_numbers)

    def test_ingest_sets_source_file(self, sample_auth_log):
        from engine.ingestion import LogIngester
        entries = LogIngester().ingest(sample_auth_log)
        assert all(e.source_file for e in entries)
        assert str(sample_auth_log) in entries[0].source_file

    def test_ingest_skips_comment_lines(self, tmp_path):
        from engine.ingestion import LogIngester
        f = tmp_path / "test.log"
        f.write_text("# this is a comment\nJan 15 09:00:01 host sshd[1]: test message\n")
        entries = LogIngester().ingest(f)
        assert len(entries) == 1
        assert not entries[0].raw_line.startswith("#")

    def test_ingest_skips_empty_lines(self, tmp_path):
        from engine.ingestion import LogIngester
        f = tmp_path / "test.log"
        f.write_text("\n\nJan 15 09:00:01 host sshd[1]: test\n\n")
        entries = LogIngester().ingest(f)
        assert len(entries) == 1

    def test_ingest_file_not_found_raises(self, tmp_path):
        from engine.ingestion import LogIngester
        with pytest.raises(FileNotFoundError):
            LogIngester().ingest(tmp_path / "nonexistent.log")

    def test_ingest_unsupported_extension_raises(self, tmp_path):
        from engine.ingestion import LogIngester
        f = tmp_path / "test.xml"
        f.write_text("<log/>")
        with pytest.raises(ValueError):
            LogIngester().ingest(f)

    def test_ingest_directory(self, tmp_path):
        from engine.ingestion import LogIngester
        (tmp_path / "a.log").write_text("Jan 15 09:00:01 host sshd[1]: message one\n")
        (tmp_path / "b.log").write_text("Jan 15 09:00:02 host sshd[2]: message two\n")
        entries = LogIngester().ingest_directory(tmp_path)
        assert len(entries) == 2


# =============================================================================
# RULE ENGINE TESTS
# =============================================================================

class TestRuleEngine:

    def test_load_rules_from_directory(self, rules_dir):
        from engine.rule_engine import RuleEngine
        rules = RuleEngine().load_rules(rules_dir)
        assert len(rules) == 4

    def test_load_rules_validates_required_fields(self, tmp_path):
        from engine.rule_engine import RuleEngine
        bad = tmp_path / "bad.yml"
        bad.write_text("rules:\n  - id: BAD-001\n    name: Missing fields\n")
        rules = RuleEngine().load_rules(bad)
        assert len(rules) == 0   # invalid rule skipped

    def test_load_rules_invalid_risk_skipped(self, tmp_path):
        from engine.rule_engine import RuleEngine
        f = tmp_path / "r.yml"
        f.write_text("""
rules:
  - id: "X-001"
    name: "Bad Risk"
    description: "test"
    category: "Test"
    risk: "SuperCritical"
    impact: "x"
    recommendation: "y"
    condition:
      type: pattern_match
      pattern: "test"
""")
        rules = RuleEngine().load_rules(f)
        assert len(rules) == 0

    def test_pattern_match_fires(self, sample_auth_log, rules_dir):
        from engine.ingestion import LogIngester
        from engine.rule_engine import RuleEngine
        entries = LogIngester().ingest(sample_auth_log)
        rules   = RuleEngine().load_rules(rules_dir)
        matches = RuleEngine().evaluate(entries, rules)
        rule_ids = [m.rule.rule_id for m in matches]
        assert "TEST-001" in rule_ids

    def test_pattern_match_no_fire_on_missing_pattern(self, tmp_path, rules_dir):
        from engine.ingestion import LogIngester
        from engine.rule_engine import RuleEngine
        f = tmp_path / "clean.log"
        f.write_text("Jan 15 09:00:01 host sshd[1]: normal operation\n")
        entries = LogIngester().ingest(f)
        rules   = RuleEngine().load_rules(rules_dir)
        matches = RuleEngine().evaluate(entries, rules)
        rule_ids = [m.rule.rule_id for m in matches]
        assert "TEST-001" not in rule_ids

    def test_threshold_fires_at_count(self, sample_auth_log, rules_dir):
        from engine.ingestion import LogIngester
        from engine.rule_engine import RuleEngine
        entries = LogIngester().ingest(sample_auth_log)
        rules   = RuleEngine().load_rules(rules_dir)
        matches = RuleEngine().evaluate(entries, rules)
        rule_ids = [m.rule.rule_id for m in matches]
        assert "TEST-003" in rule_ids

    def test_threshold_does_not_fire_below_count(self, tmp_path, rules_dir):
        from engine.ingestion import LogIngester
        from engine.rule_engine import RuleEngine
        f = tmp_path / "few.log"
        f.write_text(
            "Jan 15 09:00:01 host sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n"
            "Jan 15 09:00:02 host sshd[2]: Failed password for root from 10.0.0.1 port 2 ssh2\n"
        )
        entries = LogIngester().ingest(f)
        rules   = RuleEngine().load_rules(rules_dir)
        matches = RuleEngine().evaluate(entries, rules)
        rule_ids = [m.rule.rule_id for m in matches]
        assert "TEST-003" not in rule_ids  # threshold is 3, only 2 lines

    def test_regex_match_fires(self, sample_auth_log, rules_dir):
        from engine.ingestion import LogIngester
        from engine.rule_engine import RuleEngine
        entries = LogIngester().ingest(sample_auth_log)
        rules   = RuleEngine().load_rules(rules_dir)
        matches = RuleEngine().evaluate(entries, rules)
        rule_ids = [m.rule.rule_id for m in matches]
        assert "TEST-004" in rule_ids

    def test_matches_sorted_by_risk(self, sample_auth_log, rules_dir):
        from engine.ingestion import LogIngester
        from engine.rule_engine import RuleEngine
        entries = LogIngester().ingest(sample_auth_log)
        rules   = RuleEngine().load_rules(rules_dir)
        matches = RuleEngine().evaluate(entries, rules)
        risks   = [m.rule.risk for m in matches]
        order   = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        ordered = sorted(risks, key=lambda r: order.get(r, 5))
        assert risks == ordered

    def test_match_contains_evidence(self, sample_auth_log, rules_dir):
        from engine.ingestion import LogIngester
        from engine.rule_engine import RuleEngine
        entries = LogIngester().ingest(sample_auth_log)
        rules   = RuleEngine().load_rules(rules_dir)
        matches = RuleEngine().evaluate(entries, rules)
        for m in matches:
            assert len(m.matched_lines) > 0

    def test_empty_entries_returns_no_matches(self, rules_dir):
        from engine.rule_engine import RuleEngine
        rules   = RuleEngine().load_rules(rules_dir)
        matches = RuleEngine().evaluate([], rules)
        assert matches == []

    def test_empty_rules_returns_no_matches(self, sample_auth_log):
        from engine.ingestion import LogIngester
        from engine.rule_engine import RuleEngine
        entries = LogIngester().ingest(sample_auth_log)
        matches = RuleEngine().evaluate(entries, [])
        assert matches == []


# =============================================================================
# FINDINGS TESTS
# =============================================================================

class TestFindingsGenerator:

    def _get_findings(self, sample_auth_log, rules_dir):
        from engine.ingestion import LogIngester
        from engine.rule_engine import RuleEngine
        from engine.findings import FindingsGenerator
        entries = LogIngester().ingest(sample_auth_log)
        rules   = RuleEngine().load_rules(rules_dir)
        matches = RuleEngine().evaluate(entries, rules)
        return FindingsGenerator().generate(matches)

    def test_findings_have_unique_ids(self, sample_auth_log, rules_dir):
        findings = self._get_findings(sample_auth_log, rules_dir)
        ids = [f.finding_id for f in findings]
        assert len(ids) == len(set(ids))

    def test_finding_ids_are_sequential(self, sample_auth_log, rules_dir):
        findings = self._get_findings(sample_auth_log, rules_dir)
        ids = [f.finding_id for f in findings]
        assert ids[0] == "F-001"
        assert ids[1] == "F-002"

    def test_all_required_fields_populated(self, sample_auth_log, rules_dir):
        findings = self._get_findings(sample_auth_log, rules_dir)
        for f in findings:
            assert f.finding_id
            assert f.rule_id
            assert f.title
            assert f.risk
            assert f.description
            assert f.impact
            assert f.recommendation

    def test_evidence_is_list(self, sample_auth_log, rules_dir):
        findings = self._get_findings(sample_auth_log, rules_dir)
        for f in findings:
            assert isinstance(f.evidence, list)
            assert len(f.evidence) > 0

    def test_evidence_max_5_lines(self, sample_auth_log, rules_dir):
        findings = self._get_findings(sample_auth_log, rules_dir)
        for f in findings:
            assert len(f.evidence) <= 5

    def test_description_includes_context(self, sample_auth_log, rules_dir):
        findings = self._get_findings(sample_auth_log, rules_dir)
        # At least one finding should mention the source IP
        descriptions = " ".join(f.description for f in findings)
        assert "192.168.1.105" in descriptions

    def test_occurrence_count_populated(self, sample_auth_log, rules_dir):
        findings = self._get_findings(sample_auth_log, rules_dir)
        counts = [f.occurrence_count for f in findings]
        assert any(c > 1 for c in counts)

    def test_no_matches_returns_empty_list(self):
        from engine.findings import FindingsGenerator
        findings = FindingsGenerator().generate([])
        assert findings == []

    def test_mitre_id_copied_from_rule(self, sample_auth_log, rules_dir):
        findings = self._get_findings(sample_auth_log, rules_dir)
        mitre_ids = [f.mitre_id for f in findings if f.mitre_id]
        assert "T1110.001" in mitre_ids


# =============================================================================
# REPORTER TESTS
# =============================================================================

class TestReportGenerator:

    def _get_findings(self, sample_auth_log, rules_dir):
        from engine.ingestion import LogIngester
        from engine.rule_engine import RuleEngine
        from engine.findings import FindingsGenerator
        entries = LogIngester().ingest(sample_auth_log)
        rules   = RuleEngine().load_rules(rules_dir)
        matches = RuleEngine().evaluate(entries, rules)
        return FindingsGenerator().generate(matches)

    def test_generates_markdown_file(self, tmp_dir, sample_auth_log, rules_dir):
        from engine.reporter import ReportGenerator
        findings = self._get_findings(sample_auth_log, rules_dir)
        paths    = ReportGenerator().generate(
            findings, tmp_dir, formats=["markdown"]
        )
        assert "markdown" in paths
        assert Path(paths["markdown"]).exists()

    def test_generates_json_file(self, tmp_dir, sample_auth_log, rules_dir):
        from engine.reporter import ReportGenerator
        findings = self._get_findings(sample_auth_log, rules_dir)
        paths    = ReportGenerator().generate(
            findings, tmp_dir, formats=["json"]
        )
        assert "json" in paths
        assert Path(paths["json"]).exists()

    def test_generates_csv_file(self, tmp_dir, sample_auth_log, rules_dir):
        from engine.reporter import ReportGenerator
        findings = self._get_findings(sample_auth_log, rules_dir)
        paths    = ReportGenerator().generate(
            findings, tmp_dir, formats=["csv"]
        )
        assert "csv" in paths
        assert Path(paths["csv"]).exists()

    def test_markdown_contains_finding_ids(self, tmp_dir, sample_auth_log, rules_dir):
        from engine.reporter import ReportGenerator
        findings = self._get_findings(sample_auth_log, rules_dir)
        paths    = ReportGenerator().generate(findings, tmp_dir, formats=["markdown"])
        md       = Path(paths["markdown"]).read_text()
        assert "F-001" in md

    def test_markdown_has_all_sections(self, tmp_dir, sample_auth_log, rules_dir):
        from engine.reporter import ReportGenerator
        findings = self._get_findings(sample_auth_log, rules_dir)
        paths    = ReportGenerator().generate(findings, tmp_dir, formats=["markdown"])
        md       = Path(paths["markdown"]).read_text()
        for section in [
            "Executive Summary",
            "Scope & Objectives",
            "Methodology",
            "Findings",
            "Conclusion",
        ]:
            assert section in md, f"Section '{section}' missing from Markdown report"

    def test_json_is_valid_and_has_findings(self, tmp_dir, sample_auth_log, rules_dir):
        from engine.reporter import ReportGenerator
        findings = self._get_findings(sample_auth_log, rules_dir)
        paths    = ReportGenerator().generate(findings, tmp_dir, formats=["json"])
        data     = json.loads(Path(paths["json"]).read_text())
        assert "findings" in data
        assert "report_metadata" in data
        assert len(data["findings"]) == len(findings)

    def test_json_metadata_includes_risk_summary(self, tmp_dir, sample_auth_log, rules_dir):
        from engine.reporter import ReportGenerator
        findings = self._get_findings(sample_auth_log, rules_dir)
        paths    = ReportGenerator().generate(findings, tmp_dir, formats=["json"])
        data     = json.loads(Path(paths["json"]).read_text())
        assert "risk_summary" in data["report_metadata"]
        assert "overall_risk" in data["report_metadata"]

    def test_csv_has_correct_headers(self, tmp_dir, sample_auth_log, rules_dir):
        from engine.reporter import ReportGenerator
        findings = self._get_findings(sample_auth_log, rules_dir)
        paths    = ReportGenerator().generate(findings, tmp_dir, formats=["csv"])
        with open(paths["csv"], newline="") as f:
            reader = csv.reader(f)
            headers = next(reader)
        assert "Finding ID" in headers
        assert "Risk Level" in headers
        assert "Recommendation" in headers

    def test_csv_row_count_matches_findings(self, tmp_dir, sample_auth_log, rules_dir):
        from engine.reporter import ReportGenerator
        findings = self._get_findings(sample_auth_log, rules_dir)
        paths    = ReportGenerator().generate(findings, tmp_dir, formats=["csv"])
        with open(paths["csv"], newline="") as f:
            rows = list(csv.reader(f))
        # rows[0] = header, rows[1:] = data
        assert len(rows) - 1 == len(findings)

    def test_empty_findings_generates_clean_report(self, tmp_dir):
        from engine.reporter import ReportGenerator
        paths = ReportGenerator().generate([], tmp_dir, formats=["markdown", "json"])
        md    = Path(paths["markdown"]).read_text()
        data  = json.loads(Path(paths["json"]).read_text())
        assert "No findings" in md or "no findings" in md.lower()
        assert data["report_metadata"]["total_findings"] == 0

    def test_scope_info_appears_in_markdown(self, tmp_dir, sample_auth_log, rules_dir):
        from engine.reporter import ReportGenerator
        findings = self._get_findings(sample_auth_log, rules_dir)
        scope    = {"organisation": "Deloitte Test Corp", "audit_period": "2024-01-15"}
        paths    = ReportGenerator().generate(
            findings, tmp_dir, scope_info=scope, formats=["markdown"]
        )
        md = Path(paths["markdown"]).read_text()
        assert "Deloitte Test Corp" in md


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestEndToEnd:
    """Full pipeline: log files → rules → findings → reports."""

    def test_full_scan_on_sample_logs(self, tmp_dir):
        """Run the complete pipeline on the project's own sample logs."""
        from engine.ingestion  import LogIngester
        from engine.rule_engine import RuleEngine
        from engine.findings   import FindingsGenerator
        from engine.reporter   import ReportGenerator

        project_root = Path(__file__).parent.parent
        auth_log     = project_root / "sample_logs" / "auth.log"
        syslog       = project_root / "sample_logs" / "syslog.log"
        rules_path   = project_root / "rules"

        if not auth_log.exists():
            pytest.skip("Sample logs not found -- skipping integration test")

        ingester  = LogIngester()
        entries   = ingester.ingest(auth_log)
        entries  += ingester.ingest(syslog)

        engine  = RuleEngine()
        rules   = engine.load_rules(rules_path)
        matches = engine.evaluate(entries, rules)

        gen      = FindingsGenerator()
        findings = gen.generate(matches)

        # We KNOW the sample logs contain attacks -- there should be findings
        assert len(findings) > 0, "Expected findings from sample attack logs"

        # At least one Critical or High finding
        risks = [f.risk for f in findings]
        assert any(r in ("Critical", "High") for r in risks), (
            "Expected at least one Critical or High finding from sample logs"
        )

        # Generate all three report formats
        reporter = ReportGenerator()
        paths    = reporter.generate(
            findings=findings,
            output_dir=tmp_dir,
            scope_info={
                "organisation": "Integration Test Corp",
                "log_files": ["auth.log", "syslog.log"],
                "rules_used": len(rules),
                "lines_processed": len(entries),
            },
            formats=["markdown", "json", "csv"],
        )

        assert len(paths) == 3
        for fmt, path in paths.items():
            assert Path(path).exists(), f"{fmt} report not created"
            assert Path(path).stat().st_size > 0, f"{fmt} report is empty"

    def test_audit_trail_completeness(self, tmp_dir):
        """
        Every finding must have: ID, rule_id, title, risk, evidence,
        impact, recommendation. This is the minimum for an auditable finding.
        """
        from engine.ingestion  import LogIngester
        from engine.rule_engine import RuleEngine
        from engine.findings   import FindingsGenerator

        project_root = Path(__file__).parent.parent
        auth_log     = project_root / "sample_logs" / "auth.log"
        rules_path   = project_root / "rules"

        if not auth_log.exists():
            pytest.skip("Sample logs not found")

        entries  = LogIngester().ingest(auth_log)
        rules    = RuleEngine().load_rules(rules_path)
        matches  = RuleEngine().evaluate(entries, rules)
        findings = FindingsGenerator().generate(matches)

        for f in findings:
            assert f.finding_id,     f"Missing finding_id in {f}"
            assert f.rule_id,        f"Missing rule_id in {f}"
            assert f.title,          f"Missing title in {f}"
            assert f.risk,           f"Missing risk in {f}"
            assert f.evidence,       f"Missing evidence in {f.finding_id}"
            assert f.impact,         f"Missing impact in {f.finding_id}"
            assert f.recommendation, f"Missing recommendation in {f.finding_id}"

    def test_json_report_is_importable(self, tmp_dir):
        """The JSON report must be parseable and structurally correct."""
        from engine.ingestion  import LogIngester
        from engine.rule_engine import RuleEngine
        from engine.findings   import FindingsGenerator
        from engine.reporter   import ReportGenerator

        project_root = Path(__file__).parent.parent
        auth_log     = project_root / "sample_logs" / "auth.log"
        rules_path   = project_root / "rules"

        if not auth_log.exists():
            pytest.skip("Sample logs not found")

        entries  = LogIngester().ingest(auth_log)
        rules    = RuleEngine().load_rules(rules_path)
        matches  = RuleEngine().evaluate(entries, rules)
        findings = FindingsGenerator().generate(matches)
        paths    = ReportGenerator().generate(
            findings, tmp_dir, formats=["json"]
        )

        with open(paths["json"]) as f:
            data = json.load(f)

        assert "report_metadata" in data
        assert "findings"        in data
        assert data["report_metadata"]["total_findings"] == len(findings)
        for finding in data["findings"]:
            assert finding["risk"] in ("Critical","High","Medium","Low","Info")
