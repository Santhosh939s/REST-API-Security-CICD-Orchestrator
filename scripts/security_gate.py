#!/usr/bin/env python3
"""
REST API Security CI/CD Orchestrator - Security Gatekeeper
===========================================================
Enterprise DevSecOps policy enforcement script.

Description:
    Parses JSON output from standard security scanning tools (Semgrep SAST,
    OWASP ZAP DAST, and OWASP Dependency-Check SCA). Evaluates findings against
    defined severity thresholds. If any 'HIGH' or 'CRITICAL' severity vulnerabilities
    are discovered, it halts execution with a non-zero exit code, breaking the CI/CD pipeline.

Supported Tools:
    - Semgrep (SAST)
    - OWASP ZAP (DAST)
    - OWASP Dependency-Check (SCA)
    - Auto-detection based on JSON schema

Author: Senior DevSecOps Engineering Team
License: ISC
"""

import os
import sys
import json
import argparse
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict

# Ensure terminal stdout/stderr handles UTF-8 safely across Windows and Linux environments
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


@dataclass
class VulnerabilityFinding:
    """Standardized representation of a vulnerability finding across any scanning tool."""
    tool: str
    rule_id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    location: str
    description: str
    cwe: Optional[str] = None


class BaseSecurityParser:
    """Abstract base parser for normalizing scanner outputs into standardized findings."""

    def __init__(self, raw_data: Dict[str, Any]):
        self.data = raw_data

    def parse(self) -> List[VulnerabilityFinding]:
        raise NotImplementedError("Subclasses must implement parse()")


class SemgrepParser(BaseSecurityParser):
    """Parses Semgrep SAST JSON reports (--json output)."""

    SEVERITY_MAP = {
        "ERROR": "HIGH",      # Semgrep maps critical/high rules to ERROR
        "WARNING": "MEDIUM",  # Semgrep maps medium rules to WARNING
        "INFO": "LOW",        # Semgrep maps info rules to LOW
        "INVENTORY": "INFO",
        "EXPERIMENT": "INFO"
    }

    def parse(self) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        results = self.data.get("results", [])

        for item in results:
            check_id = item.get("check_id", "Unknown-Semgrep-Rule")
            path = item.get("path", "unknown")
            line = item.get("start", {}).get("line", 0)
            extra = item.get("extra", {})

            # Map Semgrep severity or check metadata impact
            raw_severity = extra.get("severity", "WARNING").upper()
            metadata = extra.get("metadata", {})
            impact = metadata.get("impact", "").upper()

            # If impact is explicitly CRITICAL or HIGH, prioritize it
            if impact in ["CRITICAL", "HIGH"]:
                severity = impact
            else:
                severity = self.SEVERITY_MAP.get(raw_severity, "MEDIUM")

            # Extract CWE identifiers if present
            cwe_list = metadata.get("cwe", [])
            cwe_str = ", ".join(cwe_list) if isinstance(cwe_list, list) else str(cwe_list)

            message = extra.get("message", "").strip().split("\n")[0]

            findings.append(
                VulnerabilityFinding(
                    tool="Semgrep (SAST)",
                    rule_id=check_id,
                    title=message if message else check_id,
                    severity=severity,
                    location=f"{path}:{line}",
                    description=extra.get("message", ""),
                    cwe=cwe_str or None
                )
            )

        return findings


class ZapParser(BaseSecurityParser):
    """Parses OWASP ZAP DAST JSON reports (-J or JSON output)."""

    # ZAP Risk codes: 3 = High, 2 = Medium, 1 = Low, 0 = Informational
    RISK_MAP = {
        "3": "HIGH",
        "2": "MEDIUM",
        "1": "LOW",
        "0": "INFO"
    }

    def parse(self) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        sites = self.data.get("site", [])

        # Normalize single site vs multiple sites structure
        if isinstance(sites, dict):
            sites = [sites]

        for site in sites:
            alerts = site.get("alerts", [])
            for alert in alerts:
                risk_code = str(alert.get("riskcode", "1"))
                risk_desc = alert.get("riskdesc", "")
                
                # Deduce severity from risk code or description
                if "High" in risk_desc:
                    severity = "HIGH"
                elif "Critical" in risk_desc:
                    severity = "CRITICAL"
                elif "Medium" in risk_desc:
                    severity = "MEDIUM"
                elif "Low" in risk_desc:
                    severity = "LOW"
                else:
                    severity = self.RISK_MAP.get(risk_code, "MEDIUM")

                alert_name = alert.get("alert", "ZAP Alert")
                cwe_id = alert.get("cweid")
                cwe_str = f"CWE-{cwe_id}" if cwe_id and str(cwe_id) != "-1" else None

                # Extract first instance or target URL
                instances = alert.get("instances", [])
                uri = instances[0].get("uri", site.get("@name", "unknown-endpoint")) if instances else site.get("@name", "unknown")

                findings.append(
                    VulnerabilityFinding(
                        tool="OWASP ZAP (DAST)",
                        rule_id=f"ZAP-Plugin-{alert.get('pluginid', 'Unknown')}",
                        title=alert_name,
                        severity=severity,
                        location=uri,
                        description=alert.get("desc", "").replace("\n", " ").strip(),
                        cwe=cwe_str
                    )
                )

        return findings


class DependencyCheckParser(BaseSecurityParser):
    """Parses OWASP Dependency-Check SCA JSON reports."""

    def parse(self) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        dependencies = self.data.get("dependencies", [])

        for dep in dependencies:
            file_name = dep.get("fileName", "unknown-pkg")
            vulnerabilities = dep.get("vulnerabilities", [])

            for vuln in vulnerabilities:
                name = vuln.get("name", "Unknown-CVE")
                raw_severity = vuln.get("severity", "MEDIUM").upper()

                # Prefer CVSS v3 score if available
                cvss_v3 = vuln.get("cvssv3", {})
                if cvss_v3 and "baseSeverity" in cvss_v3:
                    severity = cvss_v3["baseSeverity"].upper()
                else:
                    severity = raw_severity if raw_severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else "MEDIUM"

                cwe = vuln.get("cwe")
                desc = vuln.get("description", "").strip()

                findings.append(
                    VulnerabilityFinding(
                        tool="OWASP Dependency-Check (SCA)",
                        rule_id=name,
                        title=f"{file_name} - {name}",
                        severity=severity,
                        location=file_name,
                        description=desc.split("\n")[0] if desc else "Known vulnerable dependency",
                        cwe=cwe
                    )
                )

        return findings


class SecurityGateOrchestrator:
    """Core evaluation engine that applies enterprise policy thresholds to security findings."""

    # Default policy: Any CRITICAL or HIGH breaks the build
    DEFAULT_FAIL_LEVELS = ["CRITICAL", "HIGH"]

    def __init__(self, fail_severities: Optional[List[str]] = None):
        self.fail_severities = [s.upper() for s in (fail_severities or self.DEFAULT_FAIL_LEVELS)]

    @staticmethod
    def detect_tool_type(data: Dict[str, Any]) -> str:
        """Autodetects the scanning tool based on characteristic JSON keys."""
        if "results" in data and ("semgrep" in str(data.get("version", "")).lower() or "paths" in data):
            return "semgrep"
        if "site" in data or "@version" in data and "site" in data:
            return "zap"
        if "dependencies" in data and "reportSchema" in data:
            return "dependency-check"
        # Fallback inspection
        if "results" in data:
            return "semgrep"
        if "site" in data:
            return "zap"
        if "dependencies" in data:
            return "dependency-check"
        return "unknown"

    def get_parser(self, tool_type: str, data: Dict[str, Any]) -> BaseSecurityParser:
        if tool_type == "semgrep":
            return SemgrepParser(data)
        elif tool_type == "zap":
            return ZapParser(data)
        elif tool_type == "dependency-check":
            return DependencyCheckParser(data)
        else:
            raise ValueError(f"Unsupported tool type '{tool_type}'. Supported tools: semgrep, zap, dependency-check")

    def evaluate(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Categorizes findings and computes gate pass/fail outcome."""
        summary = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
            "TOTAL": len(findings)
        }

        breaching_findings: List[VulnerabilityFinding] = []

        for f in findings:
            sev = f.severity.upper()
            if sev in summary:
                summary[sev] += 1
            else:
                summary["INFO"] += 1

            if sev in self.fail_severities:
                breaching_findings.append(f)

        passed = len(breaching_findings) == 0

        return {
            "passed": passed,
            "summary": summary,
            "breaching_findings": breaching_findings,
            "all_findings": findings
        }

    @staticmethod
    def print_console_report(evaluation: Dict[str, Any], report_file: str, tool: str):
        """Renders an enterprise-grade terminal report detailing findings and policy decision."""
        summary = evaluation["summary"]
        passed = evaluation["passed"]
        breaching = evaluation["breaching_findings"]

        separator = "=" * 80
        sub_separator = "-" * 80

        print("\n" + separator)
        print("  🛡️  ENTERPRISE DEVSECOPS SECURITY GATEWAY REPORT")
        print(separator)
        print(f"  Target Report  : {report_file}")
        print(f"  Tool Detected  : {tool.upper()}")
        print(f"  Total Findings : {summary['TOTAL']}")
        print(sub_separator)
        print("  FINDINGS BREAKDOWN:")
        print(f"    - CRITICAL : {summary['CRITICAL']}")
        print(f"    - HIGH     : {summary['HIGH']}")
        print(f"    - MEDIUM   : {summary['MEDIUM']}")
        print(f"    - LOW      : {summary['LOW']}")
        print(f"    - INFO     : {summary['INFO']}")
        print(sub_separator)

        if breaching:
            print("\n  ❌ SECURITY GATE BREACH: Blocking findings discovered above policy threshold!\n")
            for idx, item in enumerate(breaching, 1):
                cwe_info = f" ({item.cwe})" if item.cwe else ""
                print(f"  [{idx}] [{item.severity}] {item.title}{cwe_info}")
                print(f"      Rule ID  : {item.rule_id}")
                print(f"      Location : {item.location}")
                if item.description:
                    desc_snippet = item.description[:120] + "..." if len(item.description) > 120 else item.description
                    print(f"      Detail   : {desc_snippet}")
                print()
        else:
            print("\n  ✅ SECURITY GATE PASSED: Zero blocking findings exceeding threshold.\n")

        print(sub_separator)
        status_label = "PASSED - Pipeline Continues" if passed else "FAILED - CI/CD Build Halted"
        icon = "✔" if passed else "✖"
        print(f"  GATE DECISION : [{icon}] {status_label}")
        print(separator + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="REST API Security CI/CD Orchestrator - Security Gatekeeper CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--file", "-f",
        required=True,
        help="Path to security report JSON file (from Semgrep, ZAP, or Dependency-Check)"
    )
    parser.add_argument(
        "--tool", "-t",
        choices=["semgrep", "zap", "dependency-check", "auto"],
        default="auto",
        help="Scanner type. Default is 'auto' (inspects JSON schema structure)."
    )
    parser.add_argument(
        "--fail-on",
        default="CRITICAL,HIGH",
        help="Comma-separated list of severities that trigger build failure (default: CRITICAL,HIGH)"
    )
    parser.add_argument(
        "--export-markdown",
        help="Optional path to output GitHub Step Summary markdown file"
    )

    args = parser.parse_args()

    # 1. Validate File Existence
    if not os.path.exists(args.file):
        print(f"[!] Error: Target report file '{args.file}' was not found.", file=sys.stderr)
        sys.exit(2)

    # 2. Parse JSON Content
    try:
        with open(args.file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as err:
        print(f"[!] Error: Failed to parse JSON in '{args.file}': {err}", file=sys.stderr)
        sys.exit(2)

    # 3. Detect Tool Type
    fail_levels = [s.strip().upper() for s in args.fail_on.split(",") if s.strip()]
    orchestrator = SecurityGateOrchestrator(fail_severities=fail_levels)

    tool_type = args.tool
    if tool_type == "auto":
        tool_type = orchestrator.detect_tool_type(data)
        if tool_type == "unknown":
            print(f"[!] Warning: Could not auto-detect tool schema for '{args.file}'. Defaulting to 'semgrep'.")
            tool_type = "semgrep"

    # 4. Parse & Normalize Findings
    try:
        scanner_parser = orchestrator.get_parser(tool_type, data)
        findings = scanner_parser.parse()
    except Exception as err:
        print(f"[!] Error parsing report content with '{tool_type}' parser: {err}", file=sys.stderr)
        sys.exit(2)

    # 5. Evaluate Findings Against Security Gate Policy
    evaluation = orchestrator.evaluate(findings)

    # 6. Render Terminal Output
    orchestrator.print_console_report(evaluation, args.file, tool_type)

    # 7. Optional Markdown Export for GitHub Actions Step Summary
    if args.export_markdown:
        try:
            with open(args.export_markdown, "w", encoding="utf-8") as mf:
                mf.write(f"### 🛡️ DevSecOps Security Gate: {tool_type.upper()}\n\n")
                status_emoji = "✅ PASSED" if evaluation["passed"] else "❌ FAILED"
                mf.write(f"**Gate Status**: {status_emoji}\n\n")
                mf.write("| Severity | Count |\n|:---|:---|\n")
                for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                    mf.write(f"| **{s}** | {evaluation['summary'][s]} |\n")
                mf.write(f"| **TOTAL** | {evaluation['summary']['TOTAL']} |\n\n")

                if evaluation["breaching_findings"]:
                    mf.write("#### 🚨 Policy Violations (Critical/High):\n")
                    mf.write("| Tool | Severity | Rule / Title | Location | CWE |\n|:---|:---|:---|:---|:---|\n")
                    for b in evaluation["breaching_findings"]:
                        mf.write(f"| {b.tool} | `{b.severity}` | {b.title} | `{b.location}` | {b.cwe or 'N/A'} |\n")
            print(f"[+] Exported Markdown Step Summary to '{args.export_markdown}'")
        except Exception as e:
            print(f"[!] Warning: Could not export markdown summary: {e}", file=sys.stderr)

    # 8. Enforce Non-Zero Exit Code on Gate Failure
    if not evaluation["passed"]:
        print(f"[!] CI/CD Gate Enforcer: Exiting with status code 1 to break build.\n")
        sys.exit(1)

    print("[+] CI/CD Gate Enforcer: Gate check successful. Proceeding with workflow.\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
