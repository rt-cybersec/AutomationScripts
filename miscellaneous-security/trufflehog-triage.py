#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
trufflehog_triage.py -- TruffleHog JSON Report Triage Tool
===========================================================
Helps triage TruffleHog secret scan reports by breaking down findings
by detector type, file path, full table view, or per-detector drill-down.

Usage:
    python trufflehog_triage.py <subcommand> <report.json> [options]

Subcommands:
    detectors   Break down findings by detector type (e.g. AWS, GitHub, HexHighEntropy)
    paths       Break down findings by top-level directory/file path
    table       Print a full triage table of all findings (one row per finding)
    drill       Deep-dive into findings for a single detector type

Examples:
    python trufflehog_triage.py detectors  restic.json
    python trufflehog_triage.py paths      restic.json
    python trufflehog_triage.py table      restic.json
    python trufflehog_triage.py drill      restic.json --detector AWS
    python trufflehog_triage.py drill      restic.json --detector HexHighEntropy
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


# =============================================================================
# Helpers
# =============================================================================

def load_findings(report_path: str) -> list:
    """Load and parse a TruffleHog JSONL report file."""
    path = Path(report_path)

    if not path.exists():
        print(f"\n  [ERROR] File not found: {report_path}")
        print(f"  Make sure you ran TruffleHog first:\n")
        print(f"    trufflehog git file:///path/to/repo --no-update --json > {report_path}\n")
        sys.exit(1)

    if path.stat().st_size == 0:
        print(f"\n  [ERROR] Report file is empty: {report_path}")
        print(f"  TruffleHog found zero findings, or the scan did not complete.")
        print(f"  Try re-running without --only-verified and without 2>/dev/null\n")
        sys.exit(1)

    findings = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"  [WARN] Skipping malformed JSON on line {i}")

    if not findings:
        print(f"\n  [ERROR] No valid JSON findings found in: {report_path}\n")
        sys.exit(1)

    return findings


def get_git_field(finding: dict, field: str) -> str:
    """Safely navigate SourceMetadata -> Data -> Git -> <field>."""
    try:
        return finding["SourceMetadata"]["Data"]["Git"].get(field, "unknown")
    except (KeyError, TypeError):
        return "unknown"


def get_raw(finding: dict) -> str:
    """Return the raw matched secret string."""
    return finding.get("Raw") or finding.get("RawV2") or "N/A"


def sep(char="-", width=100):
    """Print a separator line."""
    return char * width


# =============================================================================
# Subcommand: detectors
# =============================================================================

def cmd_detectors(findings: list, report_path: str):
    """Break down all findings by detector type."""
    counter  = Counter(f.get("DetectorName", "unknown") for f in findings)
    total    = sum(counter.values())
    verified = sum(1 for f in findings if f.get("Verified") is True)

    print(f"\n  DETECTOR BREAKDOWN")
    print(f"  Report : {report_path}")
    print(f"  Total  : {total} findings  ({verified} verified, {total - verified} unverified)")
    print(f"\n  {sep()}")
    print(f"  {'COUNT':>6}   {'DETECTOR NAME':<35}   {'%':>5}   BAR")
    print(f"  {sep()}")

    for name, count in counter.most_common():
        bar = "#" * int((count / total) * 30)
        pct = (count / total) * 100
        print(f"  {count:>6}   {name:<35}   {pct:5.1f}%  {bar}")

    print(f"  {sep()}")
    print()
    print(f"  TIP: High counts on HexHighEntropy/Base64HighEntropy = likely false positives.")
    print(f"       High counts on specific services (AWS, GitHub, Stripe) = worth inspecting.")
    print()


# =============================================================================
# Subcommand: paths
# =============================================================================

def cmd_paths(findings: list, report_path: str):
    """Break down findings by top-level directory."""
    raw_paths  = [get_git_field(f, "file") for f in findings]
    top_dirs   = Counter()
    full_paths = Counter()

    for p in raw_paths:
        parts = p.replace("\\", "/").split("/")
        top_dirs[parts[0]] += 1
        if len(parts) > 1:
            full_paths["/".join(parts[:2])] += 1
        else:
            full_paths[parts[0]] += 1

    total = len(findings)
    noisy_keywords = ["vendor", "node_modules", "testdata", "test", "tests",
                      "fixtures", "mocks", "docs", "doc", "examples", "contrib"]

    print(f"\n  FILE PATH BREAKDOWN")
    print(f"  Report : {report_path}")
    print(f"  Total  : {total} findings\n")

    print(f"  -- TOP-LEVEL DIRECTORIES {'-' * 60}")
    print(f"  {'COUNT':>6}   {'% ':>5}   {'DIRECTORY':<35}   SUPPRESSION CANDIDATE?")
    print(f"  {sep()}")

    for path, count in top_dirs.most_common():
        pct      = (count / total) * 100
        suppress = ""
        if any(kw in path.lower() for kw in noisy_keywords):
            suppress = f"<- YES: add '{path}/' to .trufflehogignore"
        print(f"  {count:>6}   {pct:5.1f}%   {path:<35}   {suppress}")

    print(f"\n  -- TWO-LEVEL PATH BREAKDOWN {'-' * 57}")
    print(f"  {'COUNT':>6}   PATH")
    print(f"  {sep()}")
    for path, count in full_paths.most_common(20):
        print(f"  {count:>6}   {path}")

    print()
    print(f"  TIP: Each directory flagged as YES = one line in .trufflehogignore.")
    print()


# =============================================================================
# Subcommand: table
# =============================================================================

def cmd_table(findings: list, report_path: str):
    """Print a full triage table -- one row per finding."""
    total    = len(findings)
    verified = sum(1 for f in findings if f.get("Verified") is True)

    C1, C2, C3, C4, C5 = 4, 28, 11, 52, 34

    print(f"\n  FULL TRIAGE TABLE")
    print(f"  Report : {report_path}")
    print(f"  Total  : {total} findings  ({verified} verified, {total - verified} unverified)\n")
    print(f"  {'#':<{C1}} {'DETECTOR':<{C2}} {'VERIFIED':<{C3}} {'FILE PATH':<{C4}} {'RAW (truncated)':<{C5}}")
    print(f"  {sep('-', C1+C2+C3+C4+C5+6)}")

    for i, f in enumerate(findings, 1):
        det    = f.get("DetectorName", "?")[:C2]
        ver    = "[VERIFIED]" if f.get("Verified") else "no"
        path   = get_git_field(f, "file")[:C4]
        raw    = get_raw(f)[:C5]
        flag   = "!!!" if f.get("Verified") else "   "
        print(f"{flag} {i:<{C1}} {det:<{C2}} {ver:<{C3}} {path:<{C4}} {raw:<{C5}}")

    print()
    print(f"  LEGEND: '!!!' = Verified secret -- CRITICAL, rotate the credential immediately.")
    print()


# =============================================================================
# Subcommand: drill
# =============================================================================

def cmd_drill(findings: list, report_path: str, detector: str):
    """Deep-dive into all findings for one specific detector."""
    matches = [f for f in findings if f.get("DetectorName", "").lower() == detector.lower()]

    if not matches:
        available = sorted(set(f.get("DetectorName", "unknown") for f in findings))
        print(f"\n  [ERROR] No findings found for detector: '{detector}'")
        print(f"\n  Available detectors in this report:")
        for d in available:
            print(f"    - {d}")
        print(f"\n  Correct usage:")
        print(f"    python trufflehog_triage.py drill {report_path} --detector <name>")
        print(f"\n  Example:")
        print(f"    python trufflehog_triage.py drill {report_path} --detector {available[0] if available else 'AWS'}")
        print()
        sys.exit(1)

    verified_count = sum(1 for f in matches if f.get("Verified") is True)
    seen_raws      = Counter(get_raw(f) for f in matches)
    fake_keywords  = ["example", "dummy", "test", "placeholder", "changeme",
                      "xxxxx", "your-", "sample", "xxxxxxxxxxxx", "000000"]

    print(f"\n  DRILL-DOWN -- Detector: {detector}")
    print(f"  Report  : {report_path}")
    print(f"  Matches : {len(matches)} findings  ({verified_count} verified)\n")
    print(f"  {sep()}\n")

    # --- Deduplication summary
    print(f"  -- UNIQUE RAW VALUES (deduplication view) {'-' * 44}")
    print(f"  {'COUNT':>6}   RAW VALUE")
    print(f"  {sep('-', 65)}")
    for raw, count in seen_raws.most_common():
        note = "  <- likely placeholder/fake" if any(w in raw.lower() for w in fake_keywords) else ""
        print(f"  {count:>6}   {raw[:70]}{note}")

    # --- Per-finding detail
    print(f"\n  -- PER-FINDING DETAIL {'-' * 65}")
    for i, f in enumerate(matches, 1):
        path   = get_git_field(f, "file")
        commit = get_git_field(f, "commit")[:10]
        email  = get_git_field(f, "email")
        raw    = get_raw(f)
        status = "[VERIFIED] CRITICAL -- rotate immediately" if f.get("Verified") else "unverified"

        print(f"  [{i}/{len(matches)}]")
        print(f"    Status : {status}")
        print(f"    File   : {path}")
        print(f"    Commit : {commit}")
        print(f"    Author : {email}")
        print(f"    Raw    : {raw[:100]}")
        print()

    print(f"  TIP: If all Raw values look identical or fake, add the file paths above")
    print(f"       to .trufflehogignore to suppress them from future scans.")
    print()


# =============================================================================
# CLI setup
# =============================================================================

USAGE_EXAMPLES = """
examples:
  python trufflehog_triage.py detectors restic.json
  python trufflehog_triage.py paths     restic.json
  python trufflehog_triage.py table     restic.json
  python trufflehog_triage.py drill     restic.json --detector AWS
  python trufflehog_triage.py drill     restic.json --detector HexHighEntropy

recommended workflow:
  1. detectors  -- see which detector types are generating the most noise
  2. paths      -- see which directories are the noisiest (easy .trufflehogignore wins)
  3. table      -- bird's-eye view of all findings in one scrollable table
  4. drill      -- confirm your triage decision for each detector before suppressing
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trufflehog_triage.py",
        description="Triage TruffleHog JSON reports -- break down, inspect, and suppress findings.",
        epilog=USAGE_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", metavar="subcommand")
    sub.required = True

    # detectors
    p = sub.add_parser(
        "detectors",
        help="Break down findings by detector type  [start here]",
        description="Shows how many findings each detector produced, sorted highest to lowest.",
        epilog="Example:\n  python trufflehog_triage.py detectors restic.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("report", metavar="report.json", help="Path to TruffleHog JSON report file")

    # paths
    p = sub.add_parser(
        "paths",
        help="Break down findings by top-level directory",
        description="Shows which directories contain the most findings and flags candidates for .trufflehogignore.",
        epilog="Example:\n  python trufflehog_triage.py paths restic.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("report", metavar="report.json", help="Path to TruffleHog JSON report file")

    # table
    p = sub.add_parser(
        "table",
        help="Print every finding as one row in a triage table",
        description="One row per finding: index, detector, verified status, file path, raw value.",
        epilog="Example:\n  python trufflehog_triage.py table restic.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("report", metavar="report.json", help="Path to TruffleHog JSON report file")

    # drill
    p = sub.add_parser(
        "drill",
        help="Deep-dive into findings for one specific detector type",
        description="Shows every finding for a chosen detector with full context: file, commit, author, raw value.",
        epilog="Example:\n  python trufflehog_triage.py drill restic.json --detector AWS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("report",     metavar="report.json", help="Path to TruffleHog JSON report file")
    p.add_argument("--detector", metavar="NAME",        help="Detector name (e.g. AWS, GitHub, HexHighEntropy)", required=True)

    return parser


def main():
    # Force UTF-8 on Windows to avoid cp1252 encoding errors
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser   = build_parser()
    args     = parser.parse_args()
    findings = load_findings(args.report)

    if   args.command == "detectors":
        cmd_detectors(findings, args.report)
    elif args.command == "paths":
        cmd_paths(findings, args.report)
    elif args.command == "table":
        cmd_table(findings, args.report)
    elif args.command == "drill":
        cmd_drill(findings, args.report, args.detector)


if __name__ == "__main__":
    main()
