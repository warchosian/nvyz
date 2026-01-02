from pathlib import Path
from typing import List, Optional, Dict
import re
from math import log2

from app.core.plugin import AnalysisResult, Issue, Severity
from rich.console import Console # For internal console output, if needed

console = Console()

class SecretScanner:
    """
    Scans files for hardcoded secrets using entropy analysis and common patterns.
    """
    def __init__(self, entropy_threshold: float = 4.5, exclude_patterns: Optional[List[str]] = None, common_secret_patterns: Optional[Dict[str, str]] = None):
        self.entropy_threshold = entropy_threshold
        self.exclude_patterns = exclude_patterns if exclude_patterns is not None else []
        # Use provided patterns or default case-insensitive regexes
        self.common_secret_patterns = common_secret_patterns if common_secret_patterns is not None else {
            "api_key": r"(?i)api[_\-]?key",
            "bearer_token": r"(?i)bearer[_\-]?token",
            "password": r"(?i)password",
        }

    def _shannon_entropy(self, data: str) -> float:
        """Calculate the Shannon entropy of a string."""
        if not data:
            return 0.0
        
        # Calculate frequency of each character
        frequencies = {}
        for char in data:
            frequencies[char] = frequencies.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for freq in frequencies.values():
            probability = freq / data_len
            entropy -= probability * log2(probability)
            
        return entropy

    def scan_file(self, file_path: Path) -> List[Issue]:
        """Scans a single file for secrets."""
        issues: List[Issue] = []
        # Convert path to relative if possible, otherwise use absolute
        try:
            display_path = str(file_path.relative_to(Path.cwd()))
        except (ValueError, TypeError):
            display_path = str(file_path)

        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.splitlines()

            for i, line in enumerate(lines):
                # Basic entropy check (e.g., for long random strings)
                words = re.findall(r'\b[a-zA-Z0-9]{16,64}\b', line) # Simplified for debugging
                for word in words:
                    entropy = self._shannon_entropy(word)
                    if entropy > self.entropy_threshold:
                        issues.append(Issue(
                            file=display_path,
                            line=i + 1,
                            message=f"Potentiel secret à haute entropie détecté: '{word[:20]}...' (entropie: {entropy:.2f})",
                            severity=Severity.HIGH,
                            rule_id="SEC002",
                            tool="nvyz-secret-scanner",
                            code_snippet=line.strip()
                        ))

                # Common pattern checks
                for rule_id, pattern in self.common_secret_patterns.items():
                    if re.search(pattern, line): # Simplified check
                            issues.append(Issue(
                                file=display_path,
                                line=i + 1,
                                message=f"Secret potentiellement codé en dur détecté: '{rule_id}'",
                                severity=Severity.CRITICAL,
                                rule_id=f"SEC003-{rule_id}",
                                tool="nvyz-secret-scanner",
                                code_snippet=line.strip()
                            ))
        except Exception as e:
            console.print(f"[red]❌ Erreur lors du scan de {file_path}: {e}[/red]")
        return issues

    def scan_paths(self, paths: List[Path]) -> AnalysisResult:
        """Scans multiple paths for secrets."""
        all_issues: List[Issue] = []
        for p in paths:
            if p.is_file():
                # Apply exclude patterns
                if any(p.match(pattern) for pattern in self.exclude_patterns):
                    continue
                all_issues.extend(self.scan_file(p))
            elif p.is_dir():
                # Recursive scan for directories (simplified for now)
                for file_in_dir in p.rglob("*"):
                    if file_in_dir.is_file():
                        if any(file_in_dir.match(pattern) for pattern in self.exclude_patterns):
                            continue
                        all_issues.extend(self.scan_file(file_in_dir))
        
        return AnalysisResult(issues=all_issues)

def scan_secrets(paths: List[Path], entropy_threshold: float, exclude_patterns: List[str]) -> AnalysisResult:
    """Convenience function to perform secret scanning."""
    scanner = SecretScanner(entropy_threshold, exclude_patterns)
    return scanner.scan_paths(paths)
