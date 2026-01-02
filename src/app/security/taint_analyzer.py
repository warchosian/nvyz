from pathlib import Path
from typing import List, Optional
import re

from app.core.plugin import AnalysisResult, Issue, Severity
from rich.console import Console # For internal console output, if needed

class TaintAnalyzer:
    """
    Performs basic taint analysis based on sensitive patterns, entry points, and sinks.
    This is a simplified, pattern-based approach, not a full AST-based data flow analysis.
    """
    def __init__(self, sensitive_patterns: List[str], entry_points: List[str], sinks: List[str], console: Console):
        self.sensitive_patterns = sensitive_patterns
        self.entry_points = entry_points
        self.sinks = sinks
        self.console = console # Use passed console object

        # Re-introduce regex compilation
        self.sensitive_regexes = [re.compile(pattern, re.IGNORECASE) for pattern in sensitive_patterns]


    def _is_sensitive_data(self, line: str) -> bool:
        """Checks if a line contains data matching sensitive patterns."""
        for regex in self.sensitive_regexes:
            if regex.search(line):
                return True
        return False

    def _is_entry_point(self, file_path: Path, line: str) -> bool:
        """Checks if a line represents an entry point (e.g., user input)."""
        file_name = file_path.name
        file_path_posix = file_path.as_posix() # Ensure consistent path separators
        for ep in self.entry_points:
            if ep == file_name:
                return True
            if ep in line:
                return True
        return False

    def _is_sink(self, line: str) -> bool:
        """Checks if a line represents a sink (e.g., database query, external API call)."""
        for s in self.sinks:
            if s in line:
                return True
        return False

    def analyze_file(self, file_path: Path) -> List[Issue]:
        """Analyzes a single file for taint flow."""
        issues: List[Issue] = []
        try:
            lines = file_path.read_text(encoding='utf-8', errors='ignore').splitlines()
            
            # Check if this file contains any entry point line
            file_is_entry_point = any(self._is_entry_point(file_path, line) for line in lines)
            if not file_is_entry_point:
                 return []

            sensitive_line_found = False
            for i, line in enumerate(lines):
                if not sensitive_line_found and self._is_sensitive_data(line):
                    sensitive_line_found = True
                
                if sensitive_line_found and self._is_sink(line):
                    issues.append(Issue(
                        file=str(file_path.relative_to(Path.cwd())),
                        line=i + 1,
                        message="Potentiel flux de données sensibles vers un sink détecté.",
                        severity=Severity.CRITICAL,
                        rule_id="SEC004-TAINT",
                        tool="nvyz-taint-analyzer",
                        code_snippet=line.strip()
                    ))
        except Exception as e:
            self.console.print(f"[red]❌ Erreur lors de l'analyse de taint pour {file_path}: {e}[/red]")
        return issues

    def analyze_paths(self, paths: List[Path]) -> AnalysisResult:
        """Analyzes multiple paths for taint flow."""
        all_issues: List[Issue] = []
        for p in paths:
            if p.is_file():
                all_issues.extend(self.analyze_file(p))
            elif p.is_dir():
                for file_in_dir in p.rglob("*"):
                    if file_in_dir.is_file():
                        all_issues.extend(self.analyze_file(file_in_dir))
        
        return AnalysisResult(issues=all_issues)

def analyze_taint(paths: List[Path], sensitive_patterns: List[str], entry_points: List[str], sinks: List[str], console: Console) -> AnalysisResult:
    """Convenience function to perform taint analysis."""
    analyzer = TaintAnalyzer(sensitive_patterns, entry_points, sinks, console)
    return analyzer.analyze_paths(paths)