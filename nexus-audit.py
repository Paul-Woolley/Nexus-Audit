"""
nexus-audit.py  --  Nexus Audit Tool
==================================
CLI entry point. Run with: python nexus-audit.py <command> [options]

Or run without arguments for interactive mode:
    python nexus-audit.py

COMMANDS:
    scan        Ingest logs, apply detection rules, generate findings
    report      Generate a report from an existing findings.json file
    list-rules  Show all loaded detection rules with descriptions
    version     Print tool version

QUICKSTART:
    # Interactive mode
    python nexus-audit.py
    
    # Run a full scan and generate all report formats
    python nexus-audit.py scan \\
        --log-file sample_logs/auth.log \\
        --log-file sample_logs/syslog.log \\
        --rules    rules/ \\
        --org      "Acme Corporation" \\
        --format   all

    # List all available detection rules
    python nexus-audit.py list-rules --rules rules/

    # Generate a report from a previous findings.json
    python nexus-audit.py report \\
        --findings output/reports/scan_20240115_090000/findings.json \\
        --format markdown
"""

import argparse  # For parsing command-line arguments
import json      # For handling JSON data in reports
import logging   # For execution logging
import sys       # For system exit and stderr
from datetime import datetime, timezone  # For timestamps
from pathlib import Path  # For file path handling

# Import theme module for consistent styling
from engine.theme import Theme, Menu, Banner


# =============================================================================
# EXECUTION LOG SETUP
# =============================================================================

def _setup_execution_log(output_dir: Path) -> tuple[logging.Logger, Path]:
    """
    Set up a file-based execution log in output/logs/.

    This log records every step of the tool's execution -- what files
    were ingested, how many lines were processed, which rules fired,
    and what output files were generated. It serves as the audit trail
    for the tool itself.
    """
    log_dir  = output_dir / "logs"  # Create logs subdirectory
    log_dir.mkdir(parents=True, exist_ok=True)  # Ensure directory exists
    ts       = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")  # Timestamp for unique log file
    log_file = log_dir / f"execution_{ts}.log"  # Full path to log file

    logger = logging.getLogger("nexus_audit")  # Get or create logger instance
    logger.setLevel(logging.DEBUG)  # Set to debug level for detailed logging
    logger.handlers.clear()  # Clear any existing handlers

    # File handler -- detailed debug output
    fh = logging.FileHandler(log_file, encoding="utf-8")  # File handler with UTF-8 encoding
    fh.setLevel(logging.DEBUG)  # Log all levels to file
    fh.setFormatter(logging.Formatter(  # Custom formatter for log entries
        "%(asctime)s  [%(levelname)-8s]  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(fh)  # Add handler to logger

    return logger, log_file  # Return logger and log file path


# =============================================================================
# COMMAND: SCAN
# =============================================================================

def cmd_scan(args: argparse.Namespace) -> int:
    """
    Full scan pipeline:
        1. Ingest log files
        2. Load detection rules
        3. Evaluate rules against log entries
        4. Generate findings
        5. Write reports

    Returns 0 on success, 1 on error.
    """
    from config.settings import DEFAULT_OUTPUT_DIR  # Import default output directory
    from engine.ingestion import LogIngester       # Import log ingestion module
    from engine.rule_engine import RuleEngine       # Import rule evaluation engine
    from engine.findings import FindingsGenerator   # Import findings creation module
    from engine.reporter import ReportGenerator     # Import report generation module

    output_dir = Path(args.output_dir) if args.output_dir else DEFAULT_OUTPUT_DIR  # Use provided or default output dir
    output_dir.mkdir(parents=True, exist_ok=True)  # Ensure output directory exists

    logger, log_file = _setup_execution_log(output_dir)  # Set up execution logging
    logger.info("=" * 60)  # Log scan start header
    logger.info("NEXUS AUDIT TOOL -- SCAN STARTED")
    logger.info("=" * 60)

    # Create timestamped subdirectory for this scan
    scan_timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")  # Generate unique timestamp
    scan_output_dir = output_dir / "reports" / f"scan_{scan_timestamp}"  # Path for scan-specific output
    scan_output_dir.mkdir(parents=True, exist_ok=True)  # Create scan output directory

    # ---- 1. Ingest log files ---------------------------------------------
    ingester    = LogIngester()  # Initialize log ingester
    all_entries = []  # List to hold all log entries
    log_files   = []  # List of log file names for scope info

    # Collect log paths from --log-file and --log-dir
    paths_to_ingest: list[Path] = []  # List of paths to process

    for lf in (args.log_file or []):  # Add individual log files
        paths_to_ingest.append(Path(lf))

    if args.log_dir:  # If directory specified, add .log/.txt files
        log_dir = Path(args.log_dir)
        if not log_dir.is_dir():
            Menu.error(f"Log directory not found: {log_dir}")
            return 1
        for f in sorted(log_dir.iterdir()):  # Iterate directory contents
            if f.suffix.lower() in {".log", ".txt"}:  # Filter by extension
                paths_to_ingest.append(f)

    if not paths_to_ingest:  # No files to process
        Menu.error(
            "No log files specified. Use --log-file or --log-dir.\n"
            "  Example: python nexus-audit.py scan --log-file sample_logs/auth.log --rules rules/"
        )
        return 1

    Menu.section("INGESTING LOG FILES")  # Display section header
    for path in paths_to_ingest:  # Process each log file
        try:
            entries = ingester.ingest(path)  # Ingest and parse log file
            all_entries.extend(entries)  # Add entries to total list
            log_files.append(str(path.name))  # Record file name for scope
            Menu.success(f"{path.name}: {len(entries):,} lines")  # Display success
            logger.info(f"Ingested: {path}  ({len(entries)} lines)")  # Log ingestion
        except (FileNotFoundError, ValueError, OSError) as exc:
            Menu.warning(f"Skipped {path}: {exc}")  # Warn about skipped files
            logger.warning(f"Skipped: {path}  ({exc})")  # Log skip reason

    if not all_entries:  # Check if any entries were ingested
        Menu.error("No log entries were ingested. Check file paths and formats.")
        return 1

    Menu.info(f"Total log lines ingested: {len(all_entries):,}")  # Display total
    logger.info(f"Total entries ingested: {len(all_entries)}")  # Log total

    # ---- 2. Load detection rules -----------------------------------------
    Menu.section("LOADING DETECTION RULES")  # Display section header
    rule_engine = RuleEngine()  # Initialize rule engine

    rules_path = Path(args.rules) if args.rules else Path("rules/")  # Use provided or default rules path
    try:
        rules = rule_engine.load_rules(rules_path)  # Load rules from path
    except FileNotFoundError:
        Menu.error(f"Rules path not found: {rules_path}")
        return 1

    if not rules:  # Check if rules were loaded
        Menu.warning("No rules loaded. Check the rules directory contains .yml files.")
        logger.warning("No rules loaded")
    else:
        Menu.success(f"{len(rules)} rules loaded from {rules_path}")  # Display success
        logger.info(f"Rules loaded: {len(rules)} from {rules_path}")  # Log rule count
        for r in rules:  # Log each rule details
            logger.debug(f"  Rule: {r.rule_id} [{r.risk}] {r.name}")

    # ---- 3. Evaluate rules ------------------------------------------------
    Menu.section("EVALUATING DETECTION RULES")  # Display section header
    matches = rule_engine.evaluate(all_entries, rules)  # Evaluate rules against entries
    logger.info(f"Rule evaluation complete. Matches: {len(matches)}")  # Log match count

    # ---- 4. Generate findings ---------------------------------------------
    Menu.section("GENERATING FINDINGS")  # Display section header
    generator = FindingsGenerator()  # Initialize findings generator
    findings  = generator.generate(matches)  # Convert matches to findings

    # Risk summary
    by_risk = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}  # Initialize risk counts
    for f in findings:  # Count findings by risk level
        by_risk[f.risk] = by_risk.get(f.risk, 0) + 1

    Menu.success(f"{len(findings)} finding(s) identified")  # Display total findings
    for risk in ["Critical", "High", "Medium", "Low", "Info"]:  # Display risk breakdown
        count = by_risk.get(risk, 0)
        if count:
            Menu.result(f"  {risk}", f"{count}")
    logger.info(f"Findings: {len(findings)} | Summary: {by_risk}")  # Log findings summary

    # ---- 5. Generate reports ----------------------------------------------
    Menu.section("GENERATING REPORTS")  # Display section header
    reporter   = ReportGenerator()  # Initialize report generator
    formats    = _resolve_formats(args.format)  # Determine output formats
    scope_info = {  # Collect scope information for reports
        "organisation":    args.org or "Not specified",
        "audit_period":    f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
        "log_files":       log_files,  # List of processed log files
        "rules_used":      len(rules),  # Number of rules applied
        "lines_processed": len(all_entries),  # Total log lines processed
    }

    try:
        paths = reporter.generate(  # Generate reports in specified formats
            findings=findings,
            output_dir=scan_output_dir,
            scope_info=scope_info,
            formats=formats,
        )
    except Exception as exc:
        Menu.error(f"Report generation failed: {exc}")  # Display error
        logger.error(f"Report generation failed: {exc}", exc_info=True)  # Log error with traceback
        return 1

    for fmt, path in paths.items():  # Display generated report paths
        Menu.success(f"{fmt.upper():10s} report: {path}")
        logger.info(f"Report written: {fmt} -> {path}")  # Log report creation

    # ---- Summary -----------------------------------------------------------
    Menu.section("SCAN COMPLETE")  # Display completion header
    print(f"\n  Log lines processed : {len(all_entries):,}")  # Summary stats
    print(f"  Rules applied       : {len(rules)}")
    print(f"  Findings identified : {len(findings)}")
    if by_risk.get("Critical"):  # Display critical findings
        print(f"  {Theme.risk_color('Critical')} : {by_risk['Critical']}")
    if by_risk.get("High"):  # Display high findings
        print(f"  {Theme.risk_color('High')}     : {by_risk['High']}")
    if by_risk.get("Medium"):  # Display medium findings
        print(f"  {Theme.risk_color('Medium')}   : {by_risk['Medium']}")
    if by_risk.get("Low"):  # Display low findings
        print(f"  {Theme.risk_color('Low')}      : {by_risk['Low']}")
    print(f"\n  Execution log: {log_file}")  # Path to execution log
    print(f"  Reports directory: {scan_output_dir}\n")  # Path to reports

    logger.info("SCAN COMPLETE")  # Log completion
    return 0  # Return success code


# =============================================================================
# COMMAND: REPORT
# =============================================================================

def cmd_report(args: argparse.Namespace) -> int:
    """
    Generate a report from an existing findings JSON file.
    Useful for re-generating in a different format without re-scanning.
    """
    from config.settings import DEFAULT_OUTPUT_DIR  # Import default output directory
    from engine.findings import Finding  # Import Finding dataclass
    from engine.reporter import ReportGenerator  # Import report generator

    findings_path = Path(args.findings)  # Path to findings JSON file
    if not findings_path.exists():  # Check if file exists
        Menu.error(f"Findings file not found: {findings_path}")
        return 1

    try:
        with open(findings_path, "r", encoding="utf-8") as f:  # Open and read JSON file
            data = json.load(f)  # Parse JSON data
    except (json.JSONDecodeError, OSError) as exc:
        Menu.error(f"Cannot read findings file: {exc}")  # Handle read/parse errors
        return 1

    # Reconstruct Finding objects from JSON
    findings = []  # List to hold reconstructed findings
    for raw in data.get("findings", []):  # Iterate over findings in JSON
        f = Finding(  # Create Finding object from raw data
            finding_id=raw["finding_id"],
            rule_id=raw["rule_id"],
            rule_name=raw["rule_name"],
            title=raw["title"],
            risk=raw["risk"],
            category=raw["category"],
            description=raw["description"],
            evidence=raw["evidence"],
            impact=raw["impact"],
            recommendation=raw["recommendation"],
            source_file=raw["source_file"],  # Log file name
            first_seen=raw["first_seen"],  # First occurrence timestamp
            last_seen=raw["last_seen"],  # Last occurrence timestamp
            source_ip=raw.get("source_ip", ""),  # Attacker IP if available
            username=raw.get("username", ""),  # Username involved
            occurrence_count=raw.get("occurrence_count", 1),  # Number of occurrences
            mitre_id=raw.get("mitre_id", ""),  # MITRE technique ID
            mitre_tactic=raw.get("mitre_tactic", ""),  # MITRE tactic
        )
        findings.append(f)  # Add reconstructed finding to list

    meta       = data.get("report_metadata", {})  # Extract metadata from JSON
    scope_info = {  # Reconstruct scope information
        "organisation":    meta.get("organisation", "Not specified"),
        "audit_period":    meta.get("audit_period",  ""),
        "log_files":       meta.get("log_files",     []),
        "rules_used":      meta.get("rules_applied",  0),
        "lines_processed": meta.get("lines_processed",0),
    }

    output_dir = Path(args.output_dir) if args.output_dir else DEFAULT_OUTPUT_DIR  # Determine output directory
    reporter   = ReportGenerator()  # Initialize report generator
    formats    = _resolve_formats(args.format)  # Determine output formats

    Menu.section("GENERATING REPORTS")  # Display section header
    try:
        paths = reporter.generate(  # Generate reports
            findings=findings,
            output_dir=output_dir / "reports",
            scope_info=scope_info,
            formats=formats,
        )
    except Exception as exc:
        Menu.error(f"Report generation failed: {exc}")
        return 1

    for fmt, path in paths.items():
        Menu.success(f"{fmt.upper():10s} report: {path}")

    return 0


# =============================================================================
# COMMAND: LIST-RULES
# =============================================================================

def cmd_list_rules(args: argparse.Namespace) -> int:
    """Print all loaded detection rules with IDs, risk levels, and descriptions."""
    from engine.rule_engine import RuleEngine

    rules_path = Path(args.rules) if args.rules else Path("rules/")
    engine     = RuleEngine()
    try:
        rules = engine.load_rules(rules_path)
    except FileNotFoundError:
        Menu.error(f"Rules path not found: {rules_path}")
        return 1

    if not rules:
        print("No rules found.")
        return 0

    print(f"\n  {'ID':<12} {'RISK':<10} {'CATEGORY':<20} {'NAME'}")
    print(f"  {'-'*10}  {'-'*8}  {'-'*18}  {'-'*40}")

    categories = {}
    for rule in rules:
        categories.setdefault(rule.category, []).append(rule)

    for cat, cat_rules in sorted(categories.items()):
        print(f"\n  [{Theme.header(cat)}]")
        for rule in cat_rules:
            print(
                f"  {rule.rule_id:<12} "
                f"{Theme.risk_color(rule.risk):<20} "
                f"{rule.category:<20} "
                f"{rule.name}"
            )
            if args.verbose:
                print(f"    {rule.description[:100]}...")
                if rule.mitre_id:
                    print(f"    MITRE: {rule.mitre_id} ({rule.mitre_tactic})")

    print(f"\n  Total: {len(rules)} rules across {len(categories)} categories\n")
    return 0


# =============================================================================
# INTERACTIVE MODE
# =============================================================================

def interactive_scan() -> int:
    """Interactive scan mode with user prompts."""
    Menu.clear_screen()
    Banner.display()
    Menu.section("RUN SCAN")
    
    print("\n  Configure your scan parameters:\n")
    
    # Get log files
    log_files = []
    while True:
        log_file = Menu.get_input("Enter log file path (or leave blank to finish)")
        if not log_file:
            break
        log_path = Path(log_file)
        if not log_path.exists():
            Menu.warning(f"File not found: {log_path}")
            continue
        log_files.append(log_path)
    
    # Try to get log directory
    log_dir = ""
    if not log_files:
        log_dir = Menu.get_input("Enter log directory path (optional)")
    
    if not log_files and not log_dir:
        Menu.error("No log files specified. Scan cancelled.")
        Menu.press_enter_to_continue()
        return 1
    
    # Get rules path
    rules_path = Menu.get_input("Enter rules path", "rules/")
    
    # Get organization name
    org_name = Menu.get_input("Enter organization name (optional)")
    
    # Get output format
    print("\n  Available formats: all, markdown, json, csv")
    format_choice = Menu.get_input("Select output format", "all")
    
    # Build args namespace
    args = argparse.Namespace(
        log_file=[str(f) for f in log_files],
        log_dir=log_dir if log_dir else None,
        rules=rules_path,
        org=org_name if org_name else None,
        format=format_choice,
        output_dir=None
    )
    
    # Run scan
    print()
    result = cmd_scan(args)
    Menu.press_enter_to_continue()
    return result


def interactive_report() -> int:
    """Interactive report generation mode."""
    Menu.clear_screen()
    Banner.display()
    Menu.section("GENERATE REPORT FROM FINDINGS")
    
    print("\n  Specify the findings file and output format:\n")
    
    # Get findings file
    findings_file = Menu.get_input("Enter findings JSON file path")
    if not findings_file:
        Menu.error("No findings file specified. Operation cancelled.")
        Menu.press_enter_to_continue()
        return 1
    
    findings_path = Path(findings_file)
    if not findings_path.exists():
        Menu.error(f"Findings file not found: {findings_path}")
        Menu.press_enter_to_continue()
        return 1
    
    # Get output format
    print("\n  Available formats: all, markdown, json, csv")
    format_choice = Menu.get_input("Select output format", "markdown")
    
    # Build args namespace
    args = argparse.Namespace(
        findings=findings_file,
        format=format_choice,
        output_dir=None
    )
    
    # Run report generation
    print()
    result = cmd_report(args)
    Menu.press_enter_to_continue()
    return result


def interactive_list_rules() -> int:
    """Interactive rules listing mode."""
    Menu.clear_screen()
    Banner.display()
    Menu.section("LIST DETECTION RULES")
    
    print("\n  Specify the rules path:\n")
    
    # Get rules path
    rules_path = Menu.get_input("Enter rules path", "rules/")
    show_verbose = Menu.get_yes_no("Show detailed information (descriptions, MITRE)?", "n")
    
    # Build args namespace
    args = argparse.Namespace(
        rules=rules_path,
        verbose=show_verbose
    )
    
    # Run list rules
    print()
    result = cmd_list_rules(args)
    Menu.press_enter_to_continue()
    return result


def interactive_mode() -> int:
    """Main interactive mode loop."""
    while True:
        Menu.clear_screen()
        Banner.display()
        Menu.show_main_menu()
        
        choice = Menu.get_choice("Select option")
        
        if choice == "1":
            interactive_scan()
        elif choice == "2":
            interactive_report()
        elif choice == "3":
            interactive_list_rules()
        elif choice == "4":
            print(f"\n  {Theme.primary('Exiting Nexus Audit Tool. Goodbye!')}\n")
            return 0
        else:
            Menu.warning("Invalid option. Please select 1-4.")
            Menu.press_enter_to_continue()


# =============================================================================
# HELPERS
# =============================================================================

def _resolve_formats(format_arg: str) -> list[str]:
    """Resolve the --format argument to a list of format strings."""
    if not format_arg or format_arg.lower() == "all":
        return ["markdown", "json", "csv"]
    formats = [f.strip().lower() for f in format_arg.split(",")]
    valid   = {"markdown", "json", "csv"}
    bad     = [f for f in formats if f not in valid]
    if bad:
        Menu.warning(f"Unknown format(s): {bad}. Valid: markdown, json, csv, all")
    return [f for f in formats if f in valid]


# =============================================================================
# ARGUMENT PARSER
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nexus-audit",
        description=(
            "Nexus Audit Tool  --  CLI-based Security Log Analysis and Audit Reporting\n"
            "Ingests log files, applies YAML detection rules, and generates structured\n"
            "audit reports in Markdown, JSON, and CSV formats.\n\n"
            "Run without arguments for interactive mode."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python nexus-audit.py                    # Interactive mode\n"
            "  python nexus-audit.py scan --log-file sample_logs/auth.log --rules rules/ --format all\n"
            "  python nexus-audit.py scan --log-dir /var/log/ --rules rules/ --org 'Acme Corp'\n"
            "  python nexus-audit.py list-rules --rules rules/ --verbose\n"
            "  python nexus-audit.py report --findings output/reports/scan_20240115_090000/findings.json --format markdown\n"
        )
    )
    parser.add_argument(
        "--version", action="version", version="Nexus Audit Tool v1.1.0"
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = False  # Allow no command for interactive mode

    # ---- scan ----------------------------------------------------------------
    p_scan = sub.add_parser(
        "scan",
        help="Ingest log files, apply detection rules, generate findings and reports",
    )
    p_scan.add_argument(
        "--log-file", metavar="FILE",
        action="append", dest="log_file",
        help="Log file to ingest (can be specified multiple times)",
    )
    p_scan.add_argument(
        "--log-dir", metavar="DIR",
        help="Directory containing log files to ingest (*.log, *.txt)",
    )
    p_scan.add_argument(
        "--rules", metavar="PATH", default="rules/",
        help="Rules directory or single .yml file (default: rules/)",
    )
    p_scan.add_argument(
        "--output-dir", metavar="DIR",
        help="Output directory for reports (default: output/)",
    )
    p_scan.add_argument(
        "--format", metavar="FMT", default="all",
        help="Report format: markdown, json, csv, or all (default: all)",
    )
    p_scan.add_argument(
        "--org", metavar="NAME",
        help="Organisation name for the report header",
    )
    p_scan.set_defaults(func=cmd_scan)

    # ---- report --------------------------------------------------------------
    p_rep = sub.add_parser(
        "report",
        help="Generate a report from an existing findings JSON file",
    )
    p_rep.add_argument(
        "--findings", metavar="FILE", required=True,
        help="Path to a findings JSON file from a previous scan",
    )
    p_rep.add_argument(
        "--format", metavar="FMT", default="markdown",
        help="Report format: markdown, json, csv, or all (default: markdown)",
    )
    p_rep.add_argument(
        "--output-dir", metavar="DIR",
        help="Output directory for reports",
    )
    p_rep.set_defaults(func=cmd_report)

    # ---- list-rules ----------------------------------------------------------
    p_lr = sub.add_parser(
        "list-rules",
        help="List all available detection rules",
    )
    p_lr.add_argument(
        "--rules", metavar="PATH", default="rules/",
        help="Rules directory or file (default: rules/)",
    )
    p_lr.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show rule descriptions and MITRE mappings",
    )
    p_lr.set_defaults(func=cmd_list_rules)

    return parser


# =============================================================================
# ENTRY POINT
# =============================================================================

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()
    
    # If no command provided, enter interactive mode
    if not args.command:
        try:
            return interactive_mode()
        except KeyboardInterrupt:
            print(f"\n\n  {Theme.warning('Interrupted by user. Exiting...')}\n")
            return 0
        except Exception as exc:
            Menu.error(f"Unexpected error: {exc}")
            import traceback
            traceback.print_exc()
            return 1
    
    # Otherwise, run the specified command
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print(f"\n  {Theme.warning('Scan interrupted by operator.')}")
        return 0
    except Exception as exc:
        Menu.error(f"Unexpected error: {exc}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())