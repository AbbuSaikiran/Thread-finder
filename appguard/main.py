"""
AppGuard CLI — Main entry point.

Usage:
    python -m appguard --scan
    python -m appguard --scan --model mistral --verbose
    python -m appguard --package com.whatsapp
    python -m appguard --scan --no-llm --output json
    python -m appguard --demo
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime

# Force UTF-8 on Windows to avoid charmap encoding errors
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from rich.console import Console

from .adb_scanner import ADBScanner, ADBError
from .risk_engine import RiskEngine
from .llm_analyzer import LLMAnalyzer
from .report import ReportGenerator
from .data_models import (
    AppInfo,
    AppCertificate,
    AppSecurityReport,
    ScanSummary,
    RiskLevel,
)


console = Console()


def get_demo_apps() -> list[AppInfo]:
    """
    Generate realistic demo app data for testing without a connected device.
    """
    apps = [
        AppInfo(
            package_name="com.whatsapp",
            app_label="WhatsApp",
            version_name="2.24.10.79",
            version_code="231430079",
            installer_package="com.android.vending",
            target_sdk="34",
            min_sdk="21",
            requested_permissions=[
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_CONTACTS",
                "android.permission.WRITE_CONTACTS",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.READ_PHONE_STATE",
                "android.permission.INTERNET",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.WAKE_LOCK",
                "android.permission.VIBRATE",
            ],
            granted_permissions=[
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_CONTACTS",
                "android.permission.INTERNET",
            ],
            certificate=AppCertificate(
                signer="CN=WhatsApp, O=WhatsApp Inc., L=Menlo Park, ST=California, C=US",
                issuer="CN=WhatsApp, O=WhatsApp Inc.",
                is_self_signed=True,
            ),
        ),
        AppInfo(
            package_name="com.flashlight.super.bright",
            app_label="Super Flashlight",
            version_name="3.1.2",
            version_code="312",
            installer_package="",
            is_sideloaded=True,
            target_sdk="26",
            min_sdk="16",
            requested_permissions=[
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.READ_CONTACTS",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_BACKGROUND_LOCATION",
                "android.permission.INTERNET",
                "android.permission.READ_PHONE_STATE",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.MANAGE_EXTERNAL_STORAGE",
                "android.permission.RECEIVE_BOOT_COMPLETED",
            ],
            granted_permissions=[
                "android.permission.CAMERA",
                "android.permission.INTERNET",
                "android.permission.READ_SMS",
            ],
            certificate=AppCertificate(
                signer="CN=Android Debug, O=Android",
                issuer="CN=Android Debug, O=Android",
                is_self_signed=True,
                is_debug_signed=True,
            ),
        ),
        AppInfo(
            package_name="com.spotify.music",
            app_label="Spotify",
            version_name="8.9.42.575",
            version_code="89042575",
            installer_package="com.android.vending",
            target_sdk="34",
            min_sdk="24",
            requested_permissions=[
                "android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE",
                "android.permission.WAKE_LOCK",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.FOREGROUND_SERVICE",
            ],
            granted_permissions=[
                "android.permission.INTERNET",
                "android.permission.READ_EXTERNAL_STORAGE",
            ],
            certificate=AppCertificate(
                signer="CN=Spotify AB, O=Spotify AB, L=Stockholm, C=SE",
                issuer="CN=Spotify AB, O=Spotify AB",
                is_self_signed=True,
            ),
        ),
        AppInfo(
            package_name="com.calculator.simple",
            app_label="Calculator",
            version_name="1.0.3",
            version_code="103",
            installer_package="com.android.vending",
            target_sdk="33",
            min_sdk="21",
            requested_permissions=[
                "android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE",
            ],
            granted_permissions=[
                "android.permission.INTERNET",
            ],
            certificate=AppCertificate(
                signer="CN=SimpleTools, O=Simple Mobile Tools",
                issuer="CN=SimpleTools, O=Simple Mobile Tools",
                is_self_signed=True,
            ),
        ),
        AppInfo(
            package_name="com.shady.vpn.free",
            app_label="FreeVPN Pro",
            version_name="5.2.0",
            version_code="520",
            installer_package="",
            is_sideloaded=True,
            target_sdk="29",
            min_sdk="19",
            requested_permissions=[
                "android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE",
                "android.permission.CHANGE_NETWORK_STATE",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_BACKGROUND_LOCATION",
                "android.permission.READ_PHONE_STATE",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.CAMERA",
                "android.permission.QUERY_ALL_PACKAGES",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.WAKE_LOCK",
            ],
            granted_permissions=[
                "android.permission.INTERNET",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_PHONE_STATE",
            ],
            certificate=AppCertificate(
                signer="CN=Unknown, O=Unknown",
                issuer="CN=Unknown, O=Unknown",
                is_self_signed=True,
            ),
        ),
        AppInfo(
            package_name="com.instagram.android",
            app_label="Instagram",
            version_name="332.0.0.38.90",
            version_code="582644406",
            installer_package="com.android.vending",
            target_sdk="34",
            min_sdk="26",
            requested_permissions=[
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_CONTACTS",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.INTERNET",
                "android.permission.READ_PHONE_STATE",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.WAKE_LOCK",
                "android.permission.VIBRATE",
            ],
            granted_permissions=[
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_CONTACTS",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.INTERNET",
            ],
            certificate=AppCertificate(
                signer="CN=Instagram, O=Meta Platforms Inc.",
                issuer="CN=Instagram, O=Meta Platforms Inc.",
                is_self_signed=True,
            ),
        ),
    ]
    return apps


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="appguard",
        description=(
            "🛡️ AppGuard — LLM-Powered Android App Security Analyzer\n\n"
            "Scans installed apps via ADB, analyzes permissions and certificates,\n"
            "and uses a local Ollama LLM to generate security risk scores."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--scan",
        action="store_true",
        help="Scan all third-party apps on connected Android device",
    )
    parser.add_argument(
        "--all-apps",
        action="store_true",
        help="Include system apps in scan (default: third-party only)",
    )
    parser.add_argument(
        "--package",
        type=str,
        metavar="PKG",
        help="Scan a specific package (e.g., com.whatsapp)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="llama3.1",
        help="Ollama model name (default: llama3.1)",
    )
    parser.add_argument(
        "--top",
        type=int,
        metavar="N",
        help="Show only top N riskiest apps",
    )
    parser.add_argument(
        "--output",
        type=str,
        choices=["terminal", "json", "html"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    parser.add_argument(
        "--output-file",
        type=str,
        metavar="PATH",
        help="Output file path for json/html export",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM analysis, use rule-based scoring only",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed per-app reports with all permissions",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run with sample data (no Android device needed)",
    )

    args = parser.parse_args()

    # Require at least one action
    if not args.scan and not args.package and not args.demo:
        parser.print_help()
        console.print(
            "\n[yellow]Specify --scan, --package, or --demo to begin.[/yellow]"
        )
        sys.exit(1)

    return args


def main():
    """Main entry point for AppGuard CLI."""
    args = parse_args()

    report_gen = ReportGenerator()
    risk_engine = RiskEngine()

    # ── Banner ──
    report_gen.print_banner()

    # ── Get App Data ──
    if args.demo:
        console.print("[bold cyan]📋 Running in DEMO mode (sample data)[/bold cyan]\n")
        apps = get_demo_apps()
        summary = ScanSummary(
            device_model="Demo Device (Pixel 8 Pro)",
            android_version="14",
            total_apps_scanned=len(apps),
        )
    else:
        # Real device scan via ADB
        try:
            scanner = ADBScanner()
            console.print("[cyan]🔍 Checking for connected device...[/cyan]")
            scanner.check_device_connected()
            console.print("[green]✓ Device connected![/green]\n")

            if args.package:
                console.print(f"[cyan]Scanning package: {args.package}[/cyan]\n")
                apps = [scanner.get_package_info(args.package)]
            else:
                third_party = not args.all_apps
                apps = scanner.batch_scan(third_party_only=third_party)

            if not apps:
                console.print("[yellow]No apps found to analyze.[/yellow]")
                sys.exit(0)

            summary = scanner.build_scan_summary(apps)
            console.print()

        except ADBError as e:
            console.print(f"\n[bold red]✗ ADB Error:[/bold red] {e}")
            console.print(
                "\n[dim]Tip: Use [cyan]--demo[/cyan] to test with "
                "sample data without a device.[/dim]"
            )
            sys.exit(1)

    # ── Risk Analysis ──
    console.print("[cyan]⚡ Running security analysis...[/cyan]\n")

    reports: list[AppSecurityReport] = []
    for app in apps:
        report = risk_engine.analyze(app)
        reports.append(report)

    # ── LLM Analysis ──
    if not args.no_llm:
        analyzer = LLMAnalyzer(model=args.model)
        reports = analyzer.batch_analyze(reports)
    else:
        console.print(
            "[dim]LLM analysis skipped (--no-llm flag). "
            "Using rule-based scores only.[/dim]\n"
        )

    # ── Update Summary ──
    summary.reports = reports
    summary.total_apps_scanned = len(reports)
    summary.update_distribution()

    # ── Output ──
    report_gen.print_device_info(summary)
    report_gen.print_risk_summary(summary)
    report_gen.print_app_table(reports, top_n=args.top)

    # Verbose: detailed per-app reports
    if args.verbose:
        for report in sorted(reports, key=lambda r: r.final_risk_score, reverse=True):
            report_gen.print_detailed_report(
                report,
                show_all_permissions=True,
            )

    # Export
    if args.output == "json":
        output_path = args.output_file or f"appguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_gen.export_json(summary, reports, output_path)
    elif args.output == "html":
        output_path = args.output_file or f"appguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        report_gen.export_html(summary, reports, output_path)

    report_gen.print_footer()


if __name__ == "__main__":
    main()
