import pytest
from enum import Enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional

# Import the actual classes to test
from app.core.plugin import Severity, Issue, AnalysisResult, AnalyzerPlugin

def test_severity_enum_values():
    assert Severity.CRITICAL.value == "CRITICAL"
    assert Severity.HIGH.value == "HIGH"
    assert Severity.MEDIUM.value == "MEDIUM"
    assert Severity.WARNING.value == "WARNING"
    assert Severity.LOW.value == "LOW"
    assert Severity.INFO.value == "INFO"

def test_issue_dataclass_creation():
    issue = Issue(
        file="test.py",
        line=10,
        message="A test issue",
        severity=Severity.HIGH,
        rule_id="T001",
        tool="test-tool"
    )
    assert issue.file == "test.py"
    assert issue.line == 10
    assert issue.message == "A test issue"
    assert issue.severity == Severity.HIGH
    assert issue.rule_id == "T001"
    assert issue.tool == "test-tool"
    assert issue.column is None
    assert issue.code_snippet is None
    assert issue.fingerprint is None

def test_issue_dataclass_optional_fields():
    issue = Issue(
        file="another.js",
        message="Optional fields test",
        severity=Severity.INFO,
        rule_id="N002",
        tool="another-tool",
        column=5,
        code_snippet="console.log('hello');",
        fingerprint="abc123def"
    )
    assert issue.column == 5
    assert issue.code_snippet == "console.log('hello');"
    assert issue.fingerprint == "abc123def"

def test_analysis_result_dataclass_creation():
    result = AnalysisResult()
    assert result.issues == []
    assert result.metrics == {}
    assert result.metadata == {}

    issue1 = Issue(file="f1.py", message="Msg1", severity=Severity.LOW, rule_id="R1", tool="Tool1")
    issue2 = Issue(file="f2.py", message="Msg2", severity=Severity.MEDIUM, rule_id="R2", tool="Tool1")
    result_with_issues = AnalysisResult(
        issues=[issue1, issue2],
        metrics={"loc": 100, "complexity": 20},
        metadata={"timestamp": "now"}
    )
    assert len(result_with_issues.issues) == 2
    assert result_with_issues.metrics["loc"] == 100
    assert result_with_issues.metadata["timestamp"] == "now"

def test_analyzer_plugin_is_abstract():
    with pytest.raises(TypeError, match="Can't instantiate abstract class AnalyzerPlugin with abstract method analyze"):
        AnalyzerPlugin()

def test_concrete_analyzer_plugin_implementation():
    class ConcretePlugin(AnalyzerPlugin):
        name = "Concrete Analyzer"
        description = "A concrete implementation for testing"

        def analyze(self, path: str, **kwargs) -> AnalysisResult:
            return AnalysisResult(issues=[
                Issue(file=path, message="Found something", severity=Severity.INFO, rule_id="C001", tool="Concrete")
            ])
    
    plugin = ConcretePlugin()
    assert plugin.name == "Concrete Analyzer"
    assert plugin.description == "A concrete implementation for testing"
    
    result = plugin.analyze("test_path.py")
    assert isinstance(result, AnalysisResult)
    assert len(result.issues) == 1
    assert result.issues[0].file == "test_path.py"
    assert result.issues[0].severity == Severity.INFO

def test_analyzer_plugin_get_config_schema():
    class AnotherConcretePlugin(AnalyzerPlugin):
        name = "Another Analyzer"
        description = "Another concrete implementation"
        def analyze(self, path: str, **kwargs) -> AnalysisResult:
            return AnalysisResult()
        
        def get_config_schema(self) -> dict:
            return {"type": "object", "properties": {"enabled": {"type": "boolean"}}}
    
    plugin = AnotherConcretePlugin()
    schema = plugin.get_config_schema()
    assert isinstance(schema, dict)
    assert schema["type"] == "object"
