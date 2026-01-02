from sarif_om import (
    Run,
    Result,
    Location,
    PhysicalLocation,
    ArtifactLocation,
    Region,
    Tool,
    ToolComponent,
    ReportingDescriptor,
    SarifLog,
    Message, # New import
)
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..core.plugin import AnalysisResult, Issue, Severity

def _map_severity_to_sarif_level(severity: Severity) -> str:
    """Maps nvyz Severity to SARIF result.level."""
    if severity in [Severity.CRITICAL, Severity.HIGH]:
        return "error"
    elif severity == Severity.MEDIUM:
        return "warning"
    elif severity == Severity.LOW:
        return "note"
    else: # INFO, WARNING (from other tools)
        return "note"

def generate_sarif_report(
    analysis_results: AnalysisResult,
    tool_name: str = "nvyz Code Forge",
    tool_version: str = "0.1.0-alpha", # This should come from a config or __version__
    rules_metadata: Optional[Dict[str, Any]] = None,
) -> SarifLog:
    """
    Generates a SARIF 2.1.0 report from an nvyz AnalysisResult object.

    Args:
        analysis_results: The AnalysisResult object containing issues.
        tool_name: The name of the tool generating the report.
        tool_version: The version of the tool.
        rules_metadata: Optional dictionary mapping rule_id to detailed rule information.

    Returns:
        A SarifLog object representing the SARIF report.
    """
    results: List[Result] = []
    rules: Dict[str, ReportingDescriptor] = {}

    for issue in analysis_results.issues:
        # Define rule if not already defined
        if issue.rule_id not in rules:
            rule_metadata = rules_metadata.get(issue.rule_id, {}) if rules_metadata else {}
            rules[issue.rule_id] = ReportingDescriptor(
                id=issue.rule_id,
                name=rule_metadata.get("name", issue.rule_id),
                full_description=Message(text=rule_metadata.get("description", issue.message)),
                help_uri=rule_metadata.get("help_uri"),
            )

        # Create SARIF result
        # Normalize path: strip leading '/' for relative-looking paths
        file_path = Path(issue.file).as_posix()
        if file_path.startswith('/') and not file_path.startswith('//'):
            file_path = file_path.lstrip('/')

        physical_location = PhysicalLocation(
            artifact_location=ArtifactLocation(uri=file_path), # Use as_posix for cross-OS pathing
            region=Region(
                start_line=issue.line if issue.line is not None else 1,
                start_column=issue.column if issue.column is not None else 1,
            ),
        )
        location = Location(physical_location=physical_location)

        sarif_result = Result(
            rule_id=issue.rule_id,
            message=Message(text=issue.message),
            locations=[location],
            level=_map_severity_to_sarif_level(issue.severity),
        )
        results.append(sarif_result)

    tool_component = ToolComponent(name=tool_name, version=tool_version, rules=list(rules.values()))
    tool = Tool(driver=tool_component)
    
    run = Run(tool=tool, results=results)
    sarif_log = SarifLog(runs=[run], version="2.1.0")

    return sarif_log

