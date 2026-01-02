import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import re

from app.core.plugin import AnalysisResult, Issue, Severity
from app.security.taint_analyzer import TaintAnalyzer, analyze_taint
from rich.console import Console # Import Console to pass to analyzer

# Fixture for a dummy console object
@pytest.fixture
def mock_console():
    return MagicMock(spec=Console)

# Fixture to mock Path.cwd() to return the temp test directory
@pytest.fixture
def mock_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path

# Fixture for a dummy file path within the mocked cwd
@pytest.fixture
def dummy_file_path(mock_cwd):
    f = mock_cwd / "main.py"
    return f

# --- Tests for TaintAnalyzer ---
def test_taint_analyzer_init(mock_console):
    analyzer = TaintAnalyzer(
        sensitive_patterns=["GDPR", "PII"],
        entry_points=["input", "request"],
        sinks=["db_query", "log_data"],
        console=mock_console
    )
    assert len(analyzer.sensitive_patterns) == 2
    assert "GDPR" in analyzer.sensitive_patterns
    assert len(analyzer.entry_points) == 2
    assert len(analyzer.sinks) == 2

def test_is_sensitive_data(mock_console):
    analyzer = TaintAnalyzer(sensitive_patterns=["GDPR", "PII"], entry_points=[], sinks=[], console=mock_console)
    assert analyzer._is_sensitive_data("user_data = get_gdpr_info()") is True
    assert analyzer._is_sensitive_data("safe_data = calculate_sum()") is False

def test_is_entry_point(mock_console):
    analyzer = TaintAnalyzer(sensitive_patterns=[], entry_points=["main.py", "user_input"], sinks=[], console=mock_console)
    assert analyzer._is_entry_point(Path("src/main.py"), "data = user_input()") is True
    assert analyzer._is_entry_point(Path("src/utils.py"), "data = clean_data()") is False

def test_is_sink(mock_console):
    analyzer = TaintAnalyzer(sensitive_patterns=[], entry_points=[], sinks=["db_query", "log_data"], console=mock_console)
    assert analyzer._is_sink("execute(db_query)") is True
    assert analyzer._is_sink("print('hello')") is False

def test_analyze_file_no_taint(dummy_file_path, mock_console):
    dummy_file_path.write_text("safe_data = 1\nresult = safe_data * 2")
    analyzer = TaintAnalyzer(
        sensitive_patterns=["GDPR"], entry_points=["main.py"], sinks=["db_query"], console=mock_console
    )
    issues = analyzer.analyze_file(dummy_file_path)
    assert len(issues) == 0

def test_analyze_file_with_taint_flow(dummy_file_path, mock_console):
    dummy_file_path.write_text(
        "user_input = request.get_data()\n"
        "gdpr_data = user_input.get('GDPR')\n"
        "db_query(gdpr_data)"
    )
    analyzer = TaintAnalyzer(
        sensitive_patterns=["GDPR"], 
        entry_points=["request.get_data", "main.py"], # main.py as entry for file
        sinks=["db_query"],
        console=mock_console
    )
    issues = analyzer.analyze_file(dummy_file_path)
    assert len(issues) == 1
    assert "Potentiel flux de données sensibles vers un sink détecté" in issues[0].message
    assert issues[0].severity == Severity.CRITICAL
    assert issues[0].line == 3 # Line where sink is detected

def test_analyze_file_no_entry_point_in_file(dummy_file_path, mock_console):
    dummy_file_path.write_text("gdpr_data = 'sensitive'\ndb_query(gdpr_data)")
    analyzer = TaintAnalyzer(
        sensitive_patterns=["gdpr"], entry_points=["other_entry.py"], sinks=["db_query"], console=mock_console
    )
    issues = analyzer.analyze_file(dummy_file_path)
    assert len(issues) == 0 # Should not analyze if file is not an entry point

def test_analyze_paths_directory_with_taint(mock_cwd, mock_console):
    main_file = mock_cwd / "main.py"
    main_file.write_text(
        "user_input = request.get_data()\n"
        "gdpr_data = user_input.get('GDPR')\n"
        "db_query(gdpr_data)"
    )
    utils_file = mock_cwd / "utils.py"
    utils_file.write_text("safe_func()")

    analyzer = TaintAnalyzer(
        sensitive_patterns=["GDPR"], 
        entry_points=["main.py", "request.get_data"], 
        sinks=["db_query"],
        console=mock_console
    )
    result = analyzer.analyze_paths([mock_cwd])
    assert len(result.issues) == 1
    assert "main.py" in result.issues[0].file

# --- Tests for analyze_taint convenience function ---
def test_analyze_taint_convenience(mock_cwd, mock_console):
    f1 = mock_cwd / "api.py"
    f1.write_text(
        "user_input = get_request()\n"
        "pii_data = user_input['PII']\n"
        "log_to_db(pii_data)"
    )
    
    result = analyze_taint(
        paths=[f1],
        sensitive_patterns=["PII"],
        entry_points=["api.py", "get_request"],
        sinks=["log_to_db"],
        console=mock_console
    )
    assert len(result.issues) == 1