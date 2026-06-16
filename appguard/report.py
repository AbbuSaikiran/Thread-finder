"""
Report generator for AppGuard.

Produces rich terminal output, JSON exports, and HTML reports
for app security scan results.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich import box

from .data_models import (
    AppSecurityReport,
    FlaggedIssue,
    RiskLevel,
    ScanSummary,
)

# Force UTF-8 on Windows to avoid charmap encoding errors
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

console = Console(force_terminal=True)


class ReportGenerator:
    """Generates formatted security reports for terminal, JSON, and HTML."""

    def print_banner(self):
        """Print the AppGuard banner."""
        banner = Text()
        banner.append("╔══════════════════════════════════════════════════╗\n", style="bold cyan")
        banner.append("║", style="bold cyan")
        banner.append("  🛡️  AppGuard", style="bold white")
        banner.append("  — App Security Analyzer", style="dim white")
        banner.append("       ║\n", style="bold cyan")
        banner.append("║", style="bold cyan")
        banner.append("  Powered by Local LLM (Ollama)", style="dim cyan")
        banner.append("                   ║\n", style="bold cyan")
        banner.append("╚══════════════════════════════════════════════════╝", style="bold cyan")
        console.print(banner)
        console.print()

    def print_device_info(self, summary: ScanSummary):
        """Print device information panel."""
        device_info = Table(show_header=False, box=None, padding=(0, 2))
        device_info.add_column("Key", style="dim")
        device_info.add_column("Value", style="bold")

        device_info.add_row("📱 Device", summary.device_model)
        device_info.add_row("🤖 Android", summary.android_version)
        device_info.add_row("📊 Apps Scanned", str(summary.total_apps_scanned))
        device_info.add_row("🕐 Scan Time", summary.scan_timestamp[:19])

        panel = Panel(
            device_info,
            title="[bold]Device Information[/bold]",
            border_style="blue",
            padding=(1, 2),
        )
        console.print(panel)
        console.print()

    def print_risk_summary(self, summary: ScanSummary):
        """Print risk distribution summary with visual bar chart."""
        summary.update_distribution()
        total = summary.total_apps_scanned or 1

        # Risk distribution panel
        dist_table = Table(show_header=False, box=None, padding=(0, 1))
        dist_table.add_column("Level", width=12)
        dist_table.add_column("Bar", width=30)
        dist_table.add_column("Count", width=8, justify="right")

        levels = [
            (RiskLevel.CRITICAL, "red"),
            (RiskLevel.HIGH, "dark_orange"),
            (RiskLevel.MEDIUM, "yellow"),
            (RiskLevel.LOW, "green"),
        ]

        for level, color in levels:
            count = summary.risk_distribution.get(level.value, 0)
            pct = count / total
            bar_width = int(pct * 25)
            bar = "█" * bar_width + "░" * (25 - bar_width)

            dist_table.add_row(
                f"{level.emoji} {level.value}",
                f"[{color}]{bar}[/{color}]",
                f"[bold]{count}[/bold] ({pct:.0%})",
            )

        panel = Panel(
            dist_table,
            title="[bold]Risk Distribution[/bold]",
            border_style="yellow",
            padding=(1, 2),
        )
        console.print(panel)
        console.print()

    def print_app_table(
        self,
        reports: list[AppSecurityReport],
        top_n: Optional[int] = None,
    ):
        """
        Print the main app risk table, sorted by risk score descending.

        Args:
            reports: List of app security reports.
            top_n: Show only top N riskiest apps. None = show all.
        """
        # Sort by risk score descending
        sorted_reports = sorted(
            reports,
            key=lambda r: r.final_risk_score,
            reverse=True,
        )

        if top_n:
            sorted_reports = sorted_reports[:top_n]

        table = Table(
            title="[bold]App Security Report[/bold]",
            box=box.ROUNDED,
            show_lines=True,
            padding=(0, 1),
            title_style="bold white",
        )

        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("App Name", style="bold", min_width=20, max_width=30)
        table.add_column("Package", style="dim cyan", min_width=20, max_width=35)
        table.add_column("Risk", justify="center", width=8)
        table.add_column("Level", justify="center", width=12)
        table.add_column("Source", width=16)
        table.add_column("Top Concern", min_width=20, max_width=40)

        for idx, report in enumerate(sorted_reports, 1):
            app = report.app_info
            level = report.risk_level

            # Risk score with color
            score_color = level.color
            score_text = f"[bold {score_color}]{report.final_risk_score}/100[/bold {score_color}]"

            # Level with emoji
            level_text = f"{level.emoji} {level.value}"

            # Top concern
            top_concern = ""
            if report.llm_concerns:
                top_concern = report.llm_concerns[0][:40]
            elif report.flagged_issues:
                top_concern = report.flagged_issues[0].description[:40]
            if len(top_concern) >= 40:
                top_concern += "…"

            # Install source with color
            source = app.install_source_label
            if "Play Store" in source:
                source_styled = f"[green]{source}[/green]"
            elif "Sideloaded" in source or "Unknown" in source:
                source_styled = f"[red]{source}[/red]"
            else:
                source_styled = source

            table.add_row(
                str(idx),
                app.display_name,
                app.package_name,
                score_text,
                level_text,
                source_styled,
                top_concern,
            )

        console.print(table)
        console.print()

    def print_detailed_report(
        self,
        report: AppSecurityReport,
        show_all_permissions: bool = False,
    ):
        """
        Print a detailed report for a single app.

        Args:
            report: The app's security report.
            show_all_permissions: If True, list every permission.
        """
        app = report.app_info
        level = report.risk_level

        # Header
        console.print(
            f"\n{'━' * 60}",
            style="dim",
        )
        console.print(
            f"  {level.emoji} [bold]{app.display_name}[/bold] "
            f"[dim]({app.package_name})[/dim]"
        )
        console.print(f"{'━' * 60}", style="dim")

        # Scores
        info_table = Table(show_header=False, box=None, padding=(0, 2))
        info_table.add_column("", width=20)
        info_table.add_column("")

        info_table.add_row(
            "Risk Score",
            f"[bold {level.color}]{report.final_risk_score}/100 "
            f"({level.value})[/bold {level.color}]",
        )
        info_table.add_row(
            "Base (Rule) Score",
            f"{report.base_risk_score}/100",
        )
        info_table.add_row("Version", app.version_name or "Unknown")
        info_table.add_row("Install Source", app.install_source_label)
        info_table.add_row("Target SDK", app.target_sdk or "Unknown")
        info_table.add_row(
            "Permissions",
            f"{len(app.requested_permissions)} requested, "
            f"{len(app.dangerous_permissions)} dangerous",
        )

        console.print(info_table)

        # Flagged Issues
        if report.flagged_issues:
            console.print("\n  [bold]⚠ Flagged Issues:[/bold]")
            for issue in report.flagged_issues:
                severity_colors = {
                    "critical": "red",
                    "high": "dark_orange",
                    "medium": "yellow",
                    "low": "dim",
                }
                color = severity_colors.get(issue.severity, "white")
                console.print(
                    f"    [{color}]• [{issue.severity.upper()}] "
                    f"{issue.description} (+{issue.risk_points}pts)[/{color}]"
                )

        # LLM Analysis
        if report.llm_analysis:
            console.print(f"\n  [bold magenta]🤖 AI Analysis:[/bold magenta]")
            console.print(f"    {report.llm_analysis}")

        if report.llm_concerns:
            console.print(f"\n  [bold]Security Concerns:[/bold]")
            for concern in report.llm_concerns:
                console.print(f"    [yellow]• {concern}[/yellow]")

        if report.llm_recommendation:
            console.print(f"\n  [bold green]💡 Recommendation:[/bold green]")
            console.print(f"    {report.llm_recommendation}")

        # All permissions (verbose mode)
        if show_all_permissions and app.requested_permissions:
            console.print(f"\n  [bold]All Requested Permissions:[/bold]")
            for perm in sorted(app.requested_permissions):
                short = perm.split(".")[-1]
                granted = "✓" if perm in app.granted_permissions else "✗"
                is_dangerous = any(
                    dp.name == perm for dp in app.dangerous_permissions
                )
                style = "red" if is_dangerous else "dim"
                console.print(f"    [{style}]{granted} {short}[/{style}]")

        console.print()

    def export_json(
        self,
        summary: ScanSummary,
        reports: list[AppSecurityReport],
        output_path: str,
    ):
        """Export full scan results as JSON."""
        data = {
            "scan_info": {
                "device_model": summary.device_model,
                "android_version": summary.android_version,
                "scan_timestamp": summary.scan_timestamp,
                "total_apps": summary.total_apps_scanned,
                "risk_distribution": summary.risk_distribution,
            },
            "apps": [r.to_dict() for r in reports],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        console.print(
            f"[bold green]✓ JSON report saved:[/bold green] {output_path}"
        )

    def export_html(
        self,
        summary: ScanSummary,
        reports: list[AppSecurityReport],
        output_path: str,
    ):
        """Export scan results as a standalone HTML report."""
        sorted_reports = sorted(
            reports,
            key=lambda r: r.final_risk_score,
            reverse=True,
        )

        # Build HTML
        rows_html = ""
        for report in sorted_reports:
            app = report.app_info
            level = report.risk_level
            color_map = {
                "LOW": "#22c55e",
                "MEDIUM": "#eab308",
                "HIGH": "#f97316",
                "CRITICAL": "#ef4444",
            }
            color = color_map.get(level.value, "#888")

            top_concern = ""
            if report.llm_concerns:
                top_concern = report.llm_concerns[0]
            elif report.flagged_issues:
                top_concern = report.flagged_issues[0].description

            rows_html += f"""
            <tr>
                <td class="app-name">{app.display_name}</td>
                <td class="package">{app.package_name}</td>
                <td><span class="score" style="background:{color}20;color:{color};border:1px solid {color}">{report.final_risk_score}/100</span></td>
                <td><span class="level" style="color:{color}">{level.emoji} {level.value}</span></td>
                <td>{app.install_source_label}</td>
                <td class="concern">{top_concern}</td>
            </tr>"""

        dist = summary.risk_distribution
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AppGuard Security Report</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family:'Segoe UI',system-ui,sans-serif; background:#0f172a; color:#e2e8f0; padding:2rem; }}
        .header {{ text-align:center; margin-bottom:2rem; }}
        .header h1 {{ font-size:2rem; color:#38bdf8; }}
        .header p {{ color:#94a3b8; margin-top:0.5rem; }}
        .summary {{ display:grid; grid-template-columns:repeat(4,1fr); gap:1rem; margin-bottom:2rem; }}
        .stat {{ background:#1e293b; border-radius:12px; padding:1.5rem; text-align:center; }}
        .stat .number {{ font-size:2rem; font-weight:bold; }}
        .stat .label {{ color:#94a3b8; font-size:0.85rem; margin-top:0.25rem; }}
        table {{ width:100%; border-collapse:collapse; background:#1e293b; border-radius:12px; overflow:hidden; }}
        th {{ background:#334155; padding:1rem; text-align:left; font-size:0.85rem; text-transform:uppercase; color:#94a3b8; }}
        td {{ padding:0.75rem 1rem; border-bottom:1px solid #334155; }}
        .app-name {{ font-weight:600; color:#f8fafc; }}
        .package {{ color:#64748b; font-size:0.85rem; }}
        .score {{ padding:4px 12px; border-radius:20px; font-weight:600; font-size:0.85rem; }}
        .level {{ font-weight:600; }}
        .concern {{ color:#94a3b8; font-size:0.85rem; max-width:300px; }}
        tr:hover {{ background:#334155; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ AppGuard Security Report</h1>
        <p>{summary.device_model} · Android {summary.android_version} · {summary.scan_timestamp[:10]}</p>
    </div>
    <div class="summary">
        <div class="stat"><div class="number" style="color:#ef4444">{dist.get('CRITICAL',0)}</div><div class="label">Critical</div></div>
        <div class="stat"><div class="number" style="color:#f97316">{dist.get('HIGH',0)}</div><div class="label">High Risk</div></div>
        <div class="stat"><div class="number" style="color:#eab308">{dist.get('MEDIUM',0)}</div><div class="label">Medium</div></div>
        <div class="stat"><div class="number" style="color:#22c55e">{dist.get('LOW',0)}</div><div class="label">Low Risk</div></div>
    </div>
    <table>
        <thead><tr>
            <th>App</th><th>Package</th><th>Risk</th><th>Level</th><th>Source</th><th>Top Concern</th>
        </tr></thead>
        <tbody>{rows_html}</tbody>
    </table>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        console.print(
            f"[bold green]✓ HTML report saved:[/bold green] {output_path}"
        )

    def print_footer(self):
        """Print the closing footer."""
        console.print(
            Panel(
                "[dim]AppGuard v1.0 — All analysis is local. "
                "No data leaves your machine.\n"
                "For detailed per-app reports, use [cyan]--verbose[/cyan] flag.\n"
                "Export options: [cyan]--output json[/cyan] | "
                "[cyan]--output html[/cyan][/dim]",
                border_style="dim",
                padding=(0, 2),
            )
        )
