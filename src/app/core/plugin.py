from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    WARNING = "WARNING"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Issue:
    file: str
    message: str
    severity: Severity
    rule_id: str
    tool: str
    line: Optional[int] = None
    column: Optional[int] = None
    code_snippet: Optional[str] = None
    fingerprint: Optional[str] = None # For deduplication

@dataclass
class AnalysisResult:
    issues: List[Issue] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict) # e.g., tool version, timestamp

class AnalyzerPlugin(ABC):
    """
    Base abstract class for all nvyz analyzer plugins.
    """
    name: str
    description: str

    @abstractmethod
    def analyze(self, path: str, **kwargs) -> AnalysisResult:
        """
        Executes the analysis for the given path and returns an AnalysisResult.
        Subclasses must implement this method.
        """
        pass

    def get_config_schema(self) -> dict:
        """
        Returns a JSON schema for plugin-specific configuration options.
        """
        return {}
