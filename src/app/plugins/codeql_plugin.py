import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

from app.core.plugin import AnalyzerPlugin, AnalysisResult, Issue, Severity
from app.reporting.sarif_generator import generate_sarif_report
from sarif_om import SarifLog # For type hinting the output of CodeQL CLI parsing

class CodeQLPlugin(AnalyzerPlugin):
    """
    Plugin for integrating CodeQL static analysis.
    Calls the CodeQL CLI as a subprocess and converts results.
    """
    name: str = "CodeQL"
    description: str = "Integrates GitHub's CodeQL for advanced security analysis."
    
    def __init__(self, license_token: Optional[str] = None):
        self.license_token = license_token # Token GitHub Advanced Security
        self._check_codeql_cli()

    def _check_codeql_cli(self):
        """Checks if CodeQL CLI is available in the system's PATH."""
        if not self._find_codeql_executable():
            raise RuntimeError(
                "CodeQL CLI not found in system PATH. "
                "Please install it and ensure it's accessible."
            )

    def _find_codeql_executable(self) -> Optional[Path]:
        """Finds the CodeQL executable."""
        # This is a placeholder; in a real scenario, use shutil.which
        # or a more robust discovery mechanism.
        # For now, just assume 'codeql' is a command.
        try:
            subprocess.run(["codeql", "--version"], capture_output=True, check=True)
            return Path("codeql") # Return a dummy path if it runs
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None

    def analyze(self, path: str, ruleset: str = "security", **kwargs) -> AnalysisResult:
        """
        Calls the CodeQL CLI as a subprocess and converts the results to nvyz format.
        
        Args:
            path: The source root path to analyze.
            ruleset: The CodeQL query suite to use (e.g., "security", "security-and-quality").
            **kwargs: Additional arguments for CodeQL CLI (e.g., database path).

        Returns:
            An AnalysisResult object containing issues found by CodeQL.
        """
        source_root = Path(path).resolve()
        db_path = Path(kwargs.get("db_path", source_root / "codeql_db")).resolve()
        sarif_output_path = Path(kwargs.get("sarif_output_path", source_root / "codeql-results.sarif")).resolve()

        # 1. Create CodeQL database
        console.print(f"[blue]🔍 Création de la base de données CodeQL pour {source_root}...[/blue]")
        db_create_cmd = [
            "codeql", "database", "create", str(db_path),
            f"--language={kwargs.get('language', 'python')}", # Default to python
            f"--source-root={source_root}"
        ]
        # Add optional --github-token if provided and database is for GitHub Advanced Security
        if self.license_token:
             db_create_cmd.append(f"--github-token={self.license_token}")

        try:
            subprocess.run(db_create_cmd, check=True, capture_output=True, text=True)
            console.print("[green]✅ Base de données CodeQL créée.[/green]")
        except subprocess.CalledProcessError as e:
            console.print(f"[red]❌ Erreur lors de la création de la base de données CodeQL: {e.stderr}[/red]")
            return AnalysisResult(issues=[Issue(file="N/A", message=f"CodeQL DB creation failed: {e.stderr}", severity=Severity.CRITICAL, rule_id="CodeQL-Error", tool=self.name)])
        
        # 2. Analyze the database
        console.print(f"[blue]🩺 Analyse de la base de données CodeQL avec le ruleset '{ruleset}'...[/blue]")
        analyze_cmd = [
            "codeql", "database", "analyze", str(db_path),
            f"--queries={ruleset}",
            "--format=sarif-latest", # Use sarif-latest for compatibility
            f"--output={sarif_output_path}"
        ]
        if self.license_token:
             analyze_cmd.append(f"--github-token={self.license_token}")
        
        try:
            subprocess.run(analyze_cmd, check=True, capture_output=True, text=True)
            console.print("[green]✅ Analyse CodeQL terminée.[/green]")
        except subprocess.CalledProcessError as e:
            console.print(f"[red]❌ Erreur lors de l'analyse CodeQL: {e.stderr}[/red]")
            return AnalysisResult(issues=[Issue(file="N/A", message=f"CodeQL analysis failed: {e.stderr}", severity=Severity.CRITICAL, rule_id="CodeQL-Error", tool=self.name)])

        # 3. Convert SARIF results to nvyz AnalysisResult
        console.print("[blue]🔄 Conversion des résultats SARIF de CodeQL...[/blue]")
        try:
            # For simplicity, we'll load the SARIF and then convert to nvyz format
            # In a real scenario, sarif_generator.py might have a `from_sarif` method
            # For now, just a placeholder conversion to dummy nvyz issues
            # Actual conversion would parse the SarifLog from sarif_output_path
            
            # This is a placeholder, as the actual SARIF parsing logic is not yet in sarif_generator
            # For now, assume we get one dummy issue per SARIF report
            # If the output SARIF file is empty, this logic should handle it
            if sarif_output_path.exists() and sarif_output_path.stat().st_size > 0:
                with open(sarif_output_path, 'r', encoding='utf-8') as f:
                    sarif_data = json.load(f)
                
                # Here we would parse sarif_data to extract issues
                # For this placeholder, we create a dummy issue if any data is found
                dummy_issue = Issue(
                    file=str(source_root / "dummy_file.py"),
                    line=1,
                    message="Dummy issue from CodeQL SARIF (actual parsing to be implemented)",
                    severity=Severity.HIGH,
                    rule_id="CodeQL-Dummy",
                    tool=self.name
                )
                analysis_result = AnalysisResult(issues=[dummy_issue])
                console.print("[green]✅ Résultats CodeQL convertis (placeholder).[/green]")
                return analysis_result
            else:
                console.print("[yellow]⚠️ Le rapport SARIF de CodeQL est vide ou non trouvé.[/yellow]")
                return AnalysisResult()
        except Exception as e:
            console.print(f"[red]❌ Erreur lors de la conversion des résultats CodeQL: {e}[/red]")
            return AnalysisResult(issues=[Issue(file="N/A", message=f"CodeQL SARIF conversion failed: {e}", severity=Severity.CRITICAL, rule_id="CodeQL-Conversion-Error", tool=self.name)])

# Placeholder for console output from cli.py
from rich.console import Console
console = Console()
import json # for json.load
