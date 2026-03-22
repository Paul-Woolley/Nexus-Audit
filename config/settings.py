"""
config/settings.py
===================
Global settings for the Nexus Audit Tool.

All default values live here. Override them via environment variables
or by passing --config to the CLI.
"""

from pathlib import Path

# ---- Project root -------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ---- Default paths (all relative to project root) -----------------------
DEFAULT_RULES_DIR   = PROJECT_ROOT / "rules"
DEFAULT_OUTPUT_DIR  = PROJECT_ROOT / "output"
DEFAULT_REPORTS_DIR = PROJECT_ROOT / "output" / "reports"
DEFAULT_LOGS_DIR    = PROJECT_ROOT / "output" / "logs"
DEFAULT_SAMPLE_LOGS = PROJECT_ROOT / "sample_logs"

# ---- Supported log extensions --------------------------------------------
SUPPORTED_LOG_EXTENSIONS = {".log", ".txt", ".csv"}

# ---- Risk levels (order matters for sorting -- Critical first) ----------
RISK_LEVELS = ["Critical", "High", "Medium", "Low", "Info"]

# ---- Risk level labels (no emojis) --------------------------------------
RISK_LABELS = {
    "Critical": "CRITICAL",
    "High":     "HIGH",
    "Medium":   "MEDIUM",
    "Low":      "LOW",
    "Info":     "INFO",
}

# ---- Report metadata defaults --------------------------------------------
REPORT_TITLE       = "IT Security Audit Report"
REPORT_PREPARED_BY = "Nexus Audit Tool v1.1"
TOOL_VERSION       = "1.1.0"

# ---- Rule condition types supported --------------------------------------
CONDITION_TYPES = {
    "pattern_match":  "String pattern present in log line",
    "regex_match":    "Regular expression matches log line",
    "threshold":      "Pattern occurs N+ times within T seconds from same source",
    "field_value":    "Extracted field equals or contains a specified value",
}