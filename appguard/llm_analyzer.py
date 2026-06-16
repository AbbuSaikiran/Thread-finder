"""
LLM Analyzer for AppGuard.

Integrates with a local Ollama instance to provide AI-powered
security analysis of Android apps. Falls back gracefully if
Ollama is not running.
"""

from __future__ import annotations

import json
import re
from typing import Optional

import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .data_models import (
    AppInfo,
    AppSecurityReport,
    RiskLevel,
)


console = Console()

# Default Ollama API endpoint
OLLAMA_BASE_URL = "http://localhost:11434"


class OllamaError(Exception):
    """Raised when Ollama communication fails."""
    pass


class LLMAnalyzer:
    """
    Sends app security data to a local Ollama LLM for AI-powered
    analysis, risk assessment, and plain-language recommendations.
    """

    SYSTEM_PROMPT = """You are an expert Android mobile security analyst. \
Your job is to analyze app security profiles and provide clear, actionable \
assessments. You must respond ONLY with valid JSON — no markdown, no \
explanations outside the JSON.

Always be specific about WHY a permission or combination is concerning. \
Consider the app's apparent purpose when evaluating risk. A flashlight app \
requesting SMS access is far more suspicious than a messaging app doing so."""

    ANALYSIS_TEMPLATE = """Analyze this Android app's security profile:

APP DETAILS:
- Name: {app_name}
- Package: {package_name}
- Version: {version}
- Install Source: {install_source}
- Target SDK: {target_sdk}
- Is Sideloaded: {is_sideloaded}

REQUESTED PERMISSIONS ({perm_count} total):
{permissions_list}

CERTIFICATE:
- Signer: {cert_signer}
- Self-Signed: {cert_self_signed}
- Debug-Signed: {cert_debug}
- Expired: {cert_expired}

RULE-BASED ANALYSIS:
- Base Risk Score: {base_score}/100
- Risk Level: {risk_level}
- Flagged Issues:
{flagged_issues}

Based on this data, provide your security assessment as JSON:
{{
  "final_risk_score": <integer 0-100>,
  "risk_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "security_concerns": [
    "<concern 1 — specific and actionable>",
    "<concern 2>",
    "<concern 3>"
  ],
  "recommendation": "<1-2 sentence plain-language advice for a non-technical user>",
  "analysis_summary": "<2-3 sentence technical summary>"
}}"""

    def __init__(
        self,
        model: str = "llama3.1",
        base_url: str = OLLAMA_BASE_URL,
        timeout: int = 120,
    ):
        """
        Initialize the LLM analyzer.

        Args:
            model: Ollama model name (e.g., "llama3.1", "mistral").
            base_url: Ollama API base URL.
            timeout: Request timeout in seconds.
        """
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def check_ollama_running(self) -> bool:
        """
        Verify that Ollama server is running and responsive.

        Returns:
            True if Ollama is available.
        """
        try:
            resp = requests.get(f"{self.base_url}/", timeout=5)
            return resp.status_code == 200
        except requests.ConnectionError:
            return False
        except requests.Timeout:
            return False

    def check_model_available(self) -> bool:
        """
        Check if the specified model is pulled and available.

        Returns:
            True if the model is available locally.
        """
        try:
            resp = requests.get(
                f"{self.base_url}/api/tags",
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                # Check with and without tag suffix
                return any(
                    self.model in m or m.startswith(self.model)
                    for m in models
                )
            return False
        except (requests.RequestException, json.JSONDecodeError):
            return False

    def get_available_models(self) -> list[str]:
        """Get list of available models from Ollama."""
        try:
            resp = requests.get(
                f"{self.base_url}/api/tags",
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                return [m.get("name", "") for m in data.get("models", [])]
        except (requests.RequestException, json.JSONDecodeError):
            pass
        return []

    def analyze_app(self, report: AppSecurityReport) -> AppSecurityReport:
        """
        Send app data to LLM for security analysis and update the report.

        Args:
            report: AppSecurityReport with base risk score already calculated.

        Returns:
            Updated AppSecurityReport with LLM analysis fields populated.
        """
        app = report.app_info
        prompt = self._build_prompt(app, report)

        try:
            response = self._query_ollama(prompt)
            parsed = self._parse_llm_response(response)

            if parsed:
                # Update report with LLM findings
                if "final_risk_score" in parsed:
                    llm_score = int(parsed["final_risk_score"])
                    # Average rule-based and LLM scores (weighted)
                    report.final_risk_score = min(100, max(0,
                        int(report.base_risk_score * 0.4 + llm_score * 0.6)
                    ))

                if "risk_level" in parsed:
                    try:
                        report.risk_level = RiskLevel(parsed["risk_level"].upper())
                    except ValueError:
                        report.risk_level = RiskLevel.from_score(
                            report.final_risk_score
                        )
                else:
                    report.risk_level = RiskLevel.from_score(
                        report.final_risk_score
                    )

                report.llm_concerns = parsed.get("security_concerns", [])
                report.llm_recommendation = parsed.get("recommendation", "")
                report.llm_analysis = parsed.get("analysis_summary", "")

        except OllamaError as e:
            console.print(f"  [dim red]⚠ LLM analysis failed: {e}[/dim red]")
            # Keep rule-based scores as fallback

        return report

    def batch_analyze(
        self,
        reports: list[AppSecurityReport],
    ) -> list[AppSecurityReport]:
        """
        Analyze multiple apps with LLM.

        Args:
            reports: List of AppSecurityReports with base scores.

        Returns:
            Updated reports with LLM analysis.
        """
        if not self.check_ollama_running():
            console.print(
                "[bold red]✗ Ollama is not running.[/bold red]\n"
                "  Start it with: [cyan]ollama serve[/cyan]\n"
                "  Falling back to rule-based scoring only.\n"
            )
            return reports

        if not self.check_model_available():
            available = self.get_available_models()
            console.print(
                f"[bold red]✗ Model '{self.model}' not found.[/bold red]\n"
                f"  Pull it with: [cyan]ollama pull {self.model}[/cyan]"
            )
            if available:
                console.print(
                    f"  Available models: {', '.join(available)}"
                )
            console.print("  Falling back to rule-based scoring only.\n")
            return reports

        console.print(
            f"[bold green]✓ Ollama connected[/bold green] "
            f"(model: [cyan]{self.model}[/cyan])\n"
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TextColumn("({task.completed}/{task.total})"),
            console=console,
        ) as progress:
            task = progress.add_task(
                "[magenta]LLM analyzing apps...", total=len(reports)
            )

            for report in reports:
                app_name = report.app_info.display_name
                progress.update(
                    task,
                    description=f"[magenta]Analyzing: {app_name}",
                )
                self.analyze_app(report)
                progress.advance(task)

        return reports

    def _build_prompt(
        self, app: AppInfo, report: AppSecurityReport
    ) -> str:
        """Build the analysis prompt from app data."""
        # Format permissions list
        perms_list = "\n".join(
            f"  - {p.split('.')[-1]}"
            for p in app.requested_permissions
        ) or "  (no permissions requested)"

        # Format flagged issues
        issues_list = "\n".join(
            f"  [{issue.severity.upper()}] {issue.description}"
            for issue in report.flagged_issues
        ) or "  (no issues flagged)"

        return self.ANALYSIS_TEMPLATE.format(
            app_name=app.display_name,
            package_name=app.package_name,
            version=app.version_name or "Unknown",
            install_source=app.install_source_label,
            target_sdk=app.target_sdk or "Unknown",
            is_sideloaded=app.is_sideloaded,
            perm_count=len(app.requested_permissions),
            permissions_list=perms_list,
            cert_signer=app.certificate.signer,
            cert_self_signed=app.certificate.is_self_signed,
            cert_debug=app.certificate.is_debug_signed,
            cert_expired=app.certificate.is_expired,
            base_score=report.base_risk_score,
            risk_level=report.risk_level.value,
            flagged_issues=issues_list,
        )

    def _query_ollama(self, prompt: str) -> str:
        """
        Send a prompt to the Ollama API and return the response text.

        Args:
            prompt: The analysis prompt.

        Returns:
            Raw response text from the LLM.

        Raises:
            OllamaError: If the request fails.
        """
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {
                "temperature": 0.3,  # Low temp for consistent analysis
                "num_predict": 1024,
            },
            "format": "json",
        }

        try:
            resp = requests.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("message", {}).get("content", "")

        except requests.ConnectionError:
            raise OllamaError(
                "Cannot connect to Ollama. Is it running? "
                "Start with: ollama serve"
            )
        except requests.Timeout:
            raise OllamaError(
                f"Ollama request timed out after {self.timeout}s. "
                "The model may be too large for your hardware."
            )
        except requests.HTTPError as e:
            raise OllamaError(f"Ollama HTTP error: {e}")
        except (json.JSONDecodeError, KeyError) as e:
            raise OllamaError(f"Invalid Ollama response: {e}")

    def _parse_llm_response(self, response: str) -> Optional[dict]:
        """
        Parse the LLM's JSON response, handling common formatting issues.

        Args:
            response: Raw response text from LLM.

        Returns:
            Parsed dictionary, or None if parsing fails.
        """
        if not response:
            return None

        # Try direct JSON parse first
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # Try extracting JSON from markdown code blocks
        json_match = re.search(
            r"```(?:json)?\s*\n?(.*?)\n?```",
            response,
            re.DOTALL,
        )
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Try finding JSON object pattern
        json_match = re.search(r"\{.*\}", response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError:
                pass

        console.print(
            "[dim yellow]⚠ Could not parse LLM response as JSON. "
            "Using rule-based score.[/dim yellow]"
        )
        return None
