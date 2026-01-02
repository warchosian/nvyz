import pytest
from pathlib import Path
from sarif_om import SarifLog, Result, Tool, ToolComponent, ReportingDescriptor, Message, Location, PhysicalLocation, ArtifactLocation, Region

# Import the functions and classes to test
from app.core.plugin import AnalysisResult, Issue, Severity
from app.reporting.sarif_generator import generate_sarif_report, _map_severity_to_sarif_level

def test_map_severity_to_sarif_level():
    assert _map_severity_to_sarif_level(Severity.CRITICAL) == "error"
    assert _map_severity_to_sarif_level(Severity.HIGH) == "error"
    assert _map_severity_to_sarif_level(Severity.MEDIUM) == "warning"
    assert _map_severity_to_sarif_level(Severity.LOW) == "note"
    assert _map_severity_to_sarif_level(Severity.INFO) == "note"
    assert _map_severity_to_sarif_level(Severity.WARNING) == "note" # Custom/unknown warning levels default to note

def test_generate_sarif_report_empty_results():
    analysis_result = AnalysisResult()
    sarif_log = generate_sarif_report(analysis_result)

    assert isinstance(sarif_log, SarifLog)
    assert len(sarif_log.runs) == 1
    run = sarif_log.runs[0]
    assert run.tool.driver.name == "nvyz Code Forge"
    assert run.tool.driver.version == "0.1.0-alpha"
    assert run.results == []
    assert run.tool.driver.rules == []

def test_generate_sarif_report_single_issue():
    issue = Issue(
        file="/project/src/main.py",
        line=10,
        column=5,
        message="SQL Injection possibility",
        severity=Severity.CRITICAL,
        rule_id="SEC001",
        tool="nvyz-security"
    )
    analysis_result = AnalysisResult(issues=[issue])
    sarif_log = generate_sarif_report(analysis_result)

    assert len(sarif_log.runs[0].results) == 1
    sarif_result = sarif_log.runs[0].results[0]
    assert sarif_result.rule_id == "SEC001"
    assert sarif_result.level == "error"
    assert sarif_result.message.text == "SQL Injection possibility"
    
    location = sarif_result.locations[0]
    assert location.physical_location.artifact_location.uri == "project/src/main.py" # as_posix() removes leading / if path is relative
    assert location.physical_location.region.start_line == 10
    assert location.physical_location.region.start_column == 5

    assert len(sarif_log.runs[0].tool.driver.rules) == 1
    rule = sarif_log.runs[0].tool.driver.rules[0]
    assert rule.id == "SEC001"
    assert rule.name == "SEC001"
    assert rule.full_description.text == "SQL Injection possibility"


def test_generate_sarif_report_multiple_issues():
    issue1 = Issue(file="file1.py", message="Issue A", severity=Severity.HIGH, rule_id="A001", tool="t1")
    issue2 = Issue(file="file2.js", message="Issue B", severity=Severity.MEDIUM, rule_id="B002", tool="t1")
    analysis_result = AnalysisResult(issues=[issue1, issue2])
    sarif_log = generate_sarif_report(analysis_result)

    assert len(sarif_log.runs[0].results) == 2
    assert len(sarif_log.runs[0].tool.driver.rules) == 2 # Two distinct rules

def test_generate_sarif_report_custom_tool_info_and_rules_metadata():
    issue = Issue(file="foo.ts", message="My issue", severity=Severity.LOW, rule_id="TS001", tool="custom")
    analysis_result = AnalysisResult(issues=[issue])
    
    custom_tool_name = "My Custom Scanner"
    custom_tool_version = "v2.0"
    rules_metadata = {
        "TS001": {"name": "No Any Types", "description": "Avoid using 'any' type.", "help_uri": "https://example.com/TS001"}
    }
    
    sarif_log = generate_sarif_report(
        analysis_result,
        tool_name=custom_tool_name,
        tool_version=custom_tool_version,
        rules_metadata=rules_metadata
    )

    assert sarif_log.runs[0].tool.driver.name == custom_tool_name
    assert sarif_log.runs[0].tool.driver.version == custom_tool_version
    
    rule = sarif_log.runs[0].tool.driver.rules[0]
    assert rule.id == "TS001"
    assert rule.name == "No Any Types"
    assert isinstance(rule.full_description, Message) # Expect a Message object
    assert rule.full_description.text == "Avoid using 'any' type." # Access 'text' as an attribute
    assert rule.help_uri == "https://example.com/TS001"
