import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import re

from app.core.plugin import AnalysisResult, Issue, Severity
from app.security.secret_scanner import SecretScanner, scan_secrets

# Fixture to mock console print
@pytest.fixture(autouse=True)
def mock_console_print():
    with patch('app.security.secret_scanner.console.print') as mock_print:
        yield mock_print

# Fixture for a dummy file path
@pytest.fixture
def dummy_file_path(tmp_path):
    f = tmp_path / "test_file.py"
    return f

# --- Tests for SecretScanner._shannon_entropy ---
def test_shannon_entropy_empty_string():
    scanner = SecretScanner()
    assert scanner._shannon_entropy("") == 0.0

def test_shannon_entropy_low_entropy_string():
    scanner = SecretScanner()
    # "aaaaa" has 0 entropy
    assert scanner._shannon_entropy("aaaaa") == 0.0

def test_shannon_entropy_high_entropy_string():
    scanner = SecretScanner()
    # A random-like string should have high entropy
    entropy = scanner._shannon_entropy("abcdefghijklmnopqrstuvwxyz1234567890ABCDEF")
    assert entropy > 4.0 # Should be relatively high

# --- Tests for SecretScanner.scan_file ---
def test_scan_file_no_secrets(dummy_file_path):
    dummy_file_path.write_text("This is some safe code.")
    scanner = SecretScanner()
    issues = scanner.scan_file(dummy_file_path)
    assert len(issues) == 0

def test_scan_file_high_entropy_secret(dummy_file_path):
    # A long, random-looking string
    dummy_file_path.write_text("const API_KEY = 'azbycxdwevfugthsirjklmnopqrstuvwxyz1234567890';")
    # Use empty patterns to only test entropy detection
    scanner = SecretScanner(entropy_threshold=4.0, common_secret_patterns={}) # Lower threshold for test
    issues = scanner.scan_file(dummy_file_path)
    assert len(issues) == 1
    assert "haute entropie" in issues[0].message
    assert issues[0].severity == Severity.HIGH

def test_scan_file_common_pattern_api_key(dummy_file_path):
    scanner = SecretScanner(common_secret_patterns={"test_key": "API_KEY\\s*=\\s*['\"](\\w+)['\"]"})
    dummy_file_path.write_text("API_KEY = 'ghp_testgithubtoken1234567890'")
    issues = scanner.scan_file(dummy_file_path)
    assert len(issues) == 1
    assert "Secret potentiellement codé en dur détecté: 'test_key'" in issues[0].message
    assert issues[0].severity == Severity.CRITICAL

def test_scan_file_exception_handling(dummy_file_path, mock_console_print):
    # Simulate an error during file read (e.g., permission denied)
    with patch.object(Path, 'read_text', side_effect=IOError("Permission denied")):
        scanner = SecretScanner()
        issues = scanner.scan_file(dummy_file_path)
        assert len(issues) == 0
        mock_console_print.assert_called_once() # Error message should be printed

# --- Tests for SecretScanner.scan_paths ---
def test_scan_paths_single_file_no_secret(tmp_path):
    f1 = tmp_path / "f1.py"
    f1.write_text("safe code")
    scanner = SecretScanner()
    result = scanner.scan_paths([f1])
    assert len(result.issues) == 0

def test_scan_paths_single_file_with_secret(tmp_path):
    f1 = tmp_path / "f1.py"
    f1.write_text("API_KEY = 'test_token'")
    scanner = SecretScanner(common_secret_patterns={"api_key": "API_KEY\\s*=\\s*['\"](?P<secret>[\\w]+)['\"]"})
    result = scanner.scan_paths([f1])
    assert len(result.issues) == 1
    assert "api_key" in result.issues[0].rule_id

def test_scan_paths_directory_recursive(tmp_path):
    dir1 = tmp_path / "dir1"
    dir1.mkdir()
    f1 = dir1 / "f1.py"
    f1.write_text("API_KEY = 'secret'")
    f2 = dir1 / "subdir" / "f2.js"
    f2.parent.mkdir()
    f2.write_text("const token = 'not-a-secret';") # Not a secret based on default entropy/patterns

    scanner = SecretScanner(common_secret_patterns={"api_key": "API_KEY\\s*=\\s*['\"](?P<secret>[\\w]+)['\"]"})
    result = scanner.scan_paths([tmp_path]) # Scan from root tmp_path
    assert len(result.issues) == 1
    assert "f1.py" in result.issues[0].file # Check that filename is in the path

def test_scan_paths_with_exclude(tmp_path):
    f1 = tmp_path / "f1.py"
    f1.write_text("API_KEY = 'secret'")
    f2 = tmp_path / "ignored.py"
    f2.write_text("API_KEY = 'secret'")
    
    scanner = SecretScanner(common_secret_patterns={"api_key": "API_KEY\\s*=\\s*['\"](?P<secret>[\\w]+)['\"]"}, exclude_patterns=["ignored.py"])
    result = scanner.scan_paths([tmp_path])
    assert len(result.issues) == 1 # Only f1.py should be scanned

# --- Tests for scan_secrets convenience function ---
def test_scan_secrets_convenience(tmp_path):
    f1 = tmp_path / "f1.py"
    f1.write_text("API_KEY = 'test_secret_value'")
    
    result = scan_secrets(
        paths=[f1], 
        entropy_threshold=4.0, 
        exclude_patterns=[]
    )
    assert len(result.issues) >= 1 # Should find at least one issue with entropy or pattern
