import pytest
from unittest.mock import patch, MagicMock, call
from pathlib import Path
import os
import json
import subprocess

from app.core.plugin import AnalysisResult, Issue, Severity
from app.plugins.codeql_plugin import CodeQLPlugin

# Mock the Console for cleaner test output
@pytest.fixture(autouse=True)
def mock_console_print():
    with patch('app.plugins.codeql_plugin.console.print') as mock_print:
        yield mock_print

# Fixture for a dummy source root
@pytest.fixture
def dummy_source_root(tmp_path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "main.py").write_text("print('hello')")
    return src_dir

# Fixture to mock subprocess.run
@pytest.fixture
def mock_subprocess_run():
    with patch('subprocess.run') as mock_run:
        # Default success behavior
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Success",
            stderr=""
        )
        yield mock_run

# Fixture to mock Path.is_file/is_dir and open for SARIF output
@pytest.fixture
def mock_path_operations():
    with patch('pathlib.Path.is_file', return_value=True), \
         patch('pathlib.Path.is_dir', return_value=False), \
         patch('builtins.open', MagicMock()) as mock_open:
        yield mock_open

# Fixture to mock _find_codeql_executable to always return a path
@pytest.fixture(autouse=True)
def mock_find_codeql_executable():
    with patch('app.plugins.codeql_plugin.CodeQLPlugin._find_codeql_executable', return_value=Path("codeql")):
        yield

# --- Tests for CodeQLPlugin ---

def test_codeql_plugin_init_success():
    plugin = CodeQLPlugin(license_token="test_token")
    assert plugin.license_token == "test_token"
    assert plugin.name == "CodeQL"
    assert plugin.description == "Integrates GitHub's CodeQL for advanced security analysis."

def test_codeql_plugin_init_no_cli_raises_runtime_error():
    with patch('app.plugins.codeql_plugin.CodeQLPlugin._find_codeql_executable', return_value=None):
        with pytest.raises(RuntimeError, match="CodeQL CLI not found"):
            CodeQLPlugin()

def test_codeql_plugin_analyze_success(dummy_source_root, mock_subprocess_run):
    # Mock SARIF file content
    mock_sarif_content = {
        "runs": [
            {"results": [{"ruleId": "test-rule", "message": {"text": "Test message"}}]}
        ]
    }
    # Mock json.load to return dummy SARIF content
    with patch('json.load', return_value=mock_sarif_content):
        # Mock open to return a mock file handle with read_text
        mock_file_handle = MagicMock()
        mock_file_handle.__enter__.return_value.read.return_value = json.dumps(mock_sarif_content)
        with patch('builtins.open', return_value=mock_file_handle):
            # Mock Path.exists and stat().st_size
            with patch.object(Path, 'exists', return_value=True), \
                 patch.object(Path, 'stat', return_value=MagicMock(st_size=100)):

                plugin = CodeQLPlugin(license_token="ghs_token")
                result = plugin.analyze(
                    path=str(dummy_source_root),
                    ruleset="my-rules",
                    language="python",
                    sarif_output_path=dummy_source_root / "codeql.sarif"
                )

                assert isinstance(result, AnalysisResult)
                # Check subprocess calls (create DB, analyze DB)
                assert mock_subprocess_run.call_count == 2
                
                # Check that a dummy issue was created from mocked SARIF
                assert len(result.issues) == 1
                assert result.issues[0].rule_id == "CodeQL-Dummy"
                assert result.issues[0].message == "Dummy issue from CodeQL SARIF (actual parsing to be implemented)"

def test_codeql_plugin_analyze_db_create_failure(dummy_source_root, mock_subprocess_run):
    mock_subprocess_run.side_effect = subprocess.CalledProcessError(
        returncode=1,
        cmd="codeql database create",
        stderr="DB creation failed"
    )
    
    plugin = CodeQLPlugin()
    result = plugin.analyze(path=str(dummy_source_root))

    assert isinstance(result, AnalysisResult)
    assert len(result.issues) == 1
    assert "CodeQL DB creation failed" in result.issues[0].message
    assert result.issues[0].severity == Severity.CRITICAL

def test_codeql_plugin_analyze_sarif_empty_or_not_found(dummy_source_root, mock_subprocess_run):
    mock_subprocess_run.return_value = MagicMock(
        returncode=0,
        stdout="Success",
        stderr=""
    )
    # Mock Path.exists and stat().st_size to simulate empty/non-existent SARIF
    with patch.object(Path, 'exists', return_value=False):
        plugin = CodeQLPlugin()
        result = plugin.analyze(path=str(dummy_source_root))
        assert isinstance(result, AnalysisResult)
        assert len(result.issues) == 0 # No issues from empty SARIF