import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

from app.core.plugin import AnalyzerPlugin, AnalysisResult, Issue, Severity
# from app.integrations.sarif_converter import SarifConverter # This module is not yet created
from rich.console import Console # For internal console output, if needed

console = Console()

# Placeholder for SarifConverter.convert_sonar_to_nvyz as it's not implemented yet
class SarifConverter:
    @staticmethod
    def convert_sonar_to_nvyz(sonar_report: dict) -> AnalysisResult:
        # Dummy implementation for now
        issues = []
        if sonar_report.get("issues"):
            issues.append(Issue(
                file="dummy_sonar_file.py",
                line=1,
                message="Dummy issue from SonarQube (actual conversion to be implemented)",
                severity=Severity.MEDIUM,
                rule_id="SonarQube-Dummy",
                tool="SonarQube"
            ))
        return AnalysisResult(issues=issues)


class SonarQubePlugin(AnalyzerPlugin):
    """
    Plugin for integrating SonarQube analysis.
    Supports both online (API) and offline (SonarScanner CLI) modes.
    """
    name: str = "SonarQube"
    description: str = "Integrates SonarQube for code quality and security hotspot analysis."

    def __init__(self, mode: str = "offline", server_url: Optional[str] = None, token: Optional[str] = None):
        self.mode = mode
        self.server_url = server_url
        self.token = token
        
        if self.mode == "online" and not (self.server_url and self.token):
            raise ValueError("Server URL and token are required for online SonarQube mode.")
        if self.mode == "offline":
            self._check_sonarscanner_cli()

    def _check_sonarscanner_cli(self):
        """Checks if SonarScanner CLI is available in the system's PATH."""
        try:
            subprocess.run(["sonar-scanner", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError(
                "SonarScanner CLI not found in system PATH. "
                "Please install it and ensure it's accessible for offline mode."
            )

    def analyze(self, path: str, project_key: Optional[str] = None, **kwargs) -> AnalysisResult:
        """
        Executes SonarQube analysis based on the configured mode.
        """
        if self.mode == "online":
            if not project_key:
                raise ValueError("project_key is required for online SonarQube analysis.")
            return self._fetch_from_server(project_key, **kwargs)
        else: # offline mode
            return self._run_local_scan(Path(path), **kwargs)

    def _fetch_from_server(self, project_key: str, **kwargs) -> AnalysisResult:
        """
        Fetches existing issues from a SonarQube server via API.
        (Requires 'requests' dependency)
        """
        console.print(f"[blue]📡 Récupération des issues SonarQube pour '{project_key}' depuis {self.server_url}...[/blue]")
        # This part would use the 'requests' library to call SonarQube API
        # For now, return a dummy result
        issues: List[Issue] = []
        if project_key == "example-project-with-issues":
            issues.append(Issue(
                file="src/example.java", line=10, message="Dummy API issue", severity=Severity.CRITICAL, rule_id="SQ-API-001", tool=self.name
            ))
        console.print("[green]✅ Issues SonarQube récupérées (dummy).[/green]")
        return AnalysisResult(issues=issues)

    def _run_local_scan(self, path: Path, **kwargs) -> AnalysisResult:
        """
        Executes SonarScanner in standalone mode (without a server).
        Generates a SARIF compatible report (as per spec).
        """
        console.print(f"[blue]🔬 Lancement du scan SonarScanner local pour {path}...[/blue]")
        sonar_project_properties = kwargs.get("sonar_project_properties", path / "sonar-project.properties")
        report_output_path = path / "sonar-report.json" # As per spec

        sonar_cmd = [
            "sonar-scanner",
            f"-Dsonar.projectBaseDir={path}",
            f"-Dproject.settings={sonar_project_properties}",
            "-Dsonar.scm.disabled=true",
            f"-Dsonar.report.export.path={report_output_path}"
        ]
        # Add language-specific properties if provided in kwargs
        if kwargs.get("language"):
            sonar_cmd.append(f"-Dsonar.language={kwargs['language']}")

        try:
            subprocess.run(sonar_cmd, check=True, capture_output=True, text=True)
            console.print("[green]✅ Scan SonarScanner local terminé.[/green]")

            if report_output_path.exists():
                with open(report_output_path, 'r', encoding='utf-8') as f:
                    sonar_report_data = json.load(f)
                return SarifConverter.convert_sonar_to_nvyz(sonar_report_data)
            else:
                console.print("[yellow]⚠️ Le rapport SonarScanner n'a pas été généré ou est vide.[/yellow]")
                return AnalysisResult()

        except subprocess.CalledProcessError as e:
            console.print(f"[red]❌ Erreur lors du scan SonarScanner local: {e.stderr}[/red]")
            return AnalysisResult(issues=[Issue(file="N/A", message=f"SonarScanner failed: {e.stderr}", severity=Severity.CRITICAL, rule_id="SonarScanner-Error", tool=self.name)])
        except Exception as e:
            console.print(f"[red]❌ Une erreur inattendue est survenue lors de l'exécution de SonarScanner: {e}[/red]")
            return AnalysisResult(issues=[Issue(file="N/A", message=f"SonarScanner execution error: {e}", severity=Severity.CRITICAL, rule_id="SonarScanner-Error", tool=self.name)])
