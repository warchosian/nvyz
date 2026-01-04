import subprocess
from pathlib import Path
from typing import Dict, Any, Optional
import os
import yaml

from app.core.plugin import AnalyzerPlugin, AnalysisResult, Issue, Severity
from app.reporting.sarif_generator import generate_sarif_report
from sarif_om import SarifLog # For type hinting the output of CodeQL CLI parsing

class CodeQLPlugin(AnalyzerPlugin):
    """
    Plugin for integrating CodeQL static analysis.
    Calls the CodeQL CLI as a subprocess and converts results.
    Configuration can be provided via codeql_config.yaml.
    """
    name: str = "CodeQL"
    description: str = "Integrates GitHub's CodeQL for advanced security analysis."

    def __init__(self, license_token: Optional[str] = None, config_file: Optional[str] = None):
        self.license_token = license_token # Token GitHub Advanced Security
        self.config = self._load_config(config_file)
        self.codeql_path = self._get_codeql_path()
        self._check_codeql_cli()

    def _load_config(self, config_file: Optional[str] = None) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        if config_file is None:
            # Try default locations (prefer project-local config.yaml)
            possible_paths = [
                Path("config.yaml"),  # Project-local config (highest priority)
                Path(__file__).parent.parent.parent / "config.yaml",  # nvyz global config
                Path.home() / ".config" / "nvyz" / "config.yaml",  # User config
            ]
            for path in possible_paths:
                if path.exists():
                    config_file = str(path)
                    break

        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config_data = yaml.safe_load(f)
                    # Store both codeql and project config
                    self.project_config = config_data.get('project', {})
                    return config_data.get('codeql', {})
            except Exception as e:
                print(f"Warning: Could not load config from {config_file}: {e}")

        self.project_config = {}
        return {}

    def _get_codeql_path(self) -> str:
        """Get the CodeQL CLI path from config or environment."""
        # Priority: 1. Config file, 2. Environment variable, 3. Default 'codeql'
        cli_path = self.config.get('cli_path')
        if not cli_path:
            cli_path = os.getenv('CODEQL_PATH', 'codeql')
        return str(cli_path)

    def _check_codeql_cli(self):
        """Checks if CodeQL CLI is available."""
        if not self._find_codeql_executable():
            raise RuntimeError(
                f"CodeQL CLI not found at: {self.codeql_path}\n"
                f"Please install CodeQL or update codeql_config.yaml with the correct path.\n"
                f"Current config: {self.config}"
            )

    def _find_codeql_executable(self) -> Optional[Path]:
        """Finds the CodeQL executable using configured path."""
        try:
            # Use longer timeout (30s) for first-time initialization
            subprocess.run([self.codeql_path, "--version"], capture_output=True, check=True, timeout=30)
            return Path(self.codeql_path)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def _get_project_language(self) -> str:
        """Get the project language from config."""
        # Priority: 1. CodeQL config default_language, 2. Project type, 3. Default to python
        if self.config.get('default_language'):
            return self.config.get('default_language')
        if self.project_config.get('type'):
            return self.project_config.get('type')
        return 'python'

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
        # Get language from kwargs, config, or project type
        language = kwargs.get('language', self._get_project_language())
        console.print(f"[blue]Creation de la base de donnees CodeQL pour {source_root} (langage: {language})...[/blue]", markup=False)
        db_create_cmd = [
            self.codeql_path, "database", "create", str(db_path),
            f"--language={language}",
            f"--source-root={source_root}",
            "--overwrite"  # Allow overwriting existing database
        ]
        # Add optional --github-token if provided and database is for GitHub Advanced Security
        if self.license_token:
             db_create_cmd.append(f"--github-token={self.license_token}")

        try:
            subprocess.run(db_create_cmd, check=True, capture_output=True, text=True)
            console.print("[green][OK] Base de donnees CodeQL creee.[/green]", markup=False)
        except subprocess.CalledProcessError as e:
            console.print(f"[red][ERREUR] Erreur lors de la creation de la base de donnees CodeQL: {e.stderr}[/red]", markup=False)
            return AnalysisResult(issues=[Issue(file="N/A", message=f"CodeQL DB creation failed: {e.stderr}", severity=Severity.CRITICAL, rule_id="CodeQL-Error", tool=self.name)])
        
        # 2. Analyze the database
        console.print(f"[blue]Analyse de la base de donnees CodeQL avec le ruleset '{ruleset}' (langage: {language})...[/blue]", markup=False)

        # Map common ruleset names to CodeQL query pack names based on language
        ruleset_mappings = {
            "python": {
                "security": "codeql/python-queries:codeql-suites/python-security.qls",
                "security-extended": "codeql/python-queries:codeql-suites/python-security-extended.qls",
                "security-and-quality": "codeql/python-queries:codeql-suites/python-security-and-quality.qls",
            },
            "java": {
                "security": "codeql/java-queries:codeql-suites/java-security.qls",
                "security-extended": "codeql/java-queries:codeql-suites/java-security-extended.qls",
                "security-and-quality": "codeql/java-queries:codeql-suites/java-security-and-quality.qls",
            },
            "javascript": {
                "security": "codeql/javascript-queries:codeql-suites/javascript-security.qls",
                "security-extended": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
                "security-and-quality": "codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls",
            },
            "php": {
                "security": "codeql/php-queries:codeql-suites/php-security.qls",
                "security-extended": "codeql/php-queries:codeql-suites/php-security-extended.qls",
                "security-and-quality": "codeql/php-queries:codeql-suites/php-security-and-quality.qls",
            },
        }

        # Get language-specific mapping or use original ruleset
        language_mapping = ruleset_mappings.get(language, {})
        query_spec = language_mapping.get(ruleset, ruleset)

        analyze_cmd = [
            self.codeql_path, "database", "analyze", str(db_path),
            query_spec,  # Query suite spec
            "--format=sarif-latest", # Use sarif-latest for compatibility
            f"--output={sarif_output_path}"
        ]
        if self.license_token:
             analyze_cmd.append(f"--github-token={self.license_token}")

        try:
            subprocess.run(analyze_cmd, check=True, capture_output=True, text=True)
            console.print("[green][OK] Analyse CodeQL terminee.[/green]", markup=False)
        except subprocess.CalledProcessError as e:
            console.print(f"[red][ERREUR] Erreur lors de l'analyse CodeQL: {e.stderr}[/red]", markup=False)
            return AnalysisResult(issues=[Issue(file="N/A", message=f"CodeQL analysis failed: {e.stderr}", severity=Severity.CRITICAL, rule_id="CodeQL-Error", tool=self.name)])

        # 3. Convert SARIF results to nvyz AnalysisResult
        console.print("[blue]Conversion des resultats SARIF de CodeQL...[/blue]", markup=False)
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
                console.print("[green][OK] Resultats CodeQL convertis (placeholder).[/green]", markup=False)
                return analysis_result
            else:
                console.print("[yellow][WARNING] Le rapport SARIF de CodeQL est vide ou non trouve.[/yellow]", markup=False)
                return AnalysisResult()
        except Exception as e:
            console.print(f"[red][ERREUR] Erreur lors de la conversion des resultats CodeQL: {e}[/red]", markup=False)
            return AnalysisResult(issues=[Issue(file="N/A", message=f"CodeQL SARIF conversion failed: {e}", severity=Severity.CRITICAL, rule_id="CodeQL-Conversion-Error", tool=self.name)])

# Placeholder for console output from cli.py
from rich.console import Console
console = Console()
import json # for json.load
