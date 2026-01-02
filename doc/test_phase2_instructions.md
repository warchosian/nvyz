# Instructions pour la création des tests unitaires de la Phase 2

Pour continuer, veuillez suivre les étapes suivantes pour créer les répertoires de tests et les fichiers de test correspondants.

### Étape 1 : Créer les répertoires de tests

Exécutez les commandes suivantes dans votre terminal, à la racine du projet `nvyz` :

```bash
mkdir -p tests/plugins
mkdir -p tests/security
```

### Étape 2 : Créer le fichier `tests/plugins/test_codeql_plugin.py`

Créez un fichier nommé `test_codeql_plugin.py` dans le répertoire `tests/plugins/` et copiez-y le contenu suivant :

```python
import pytest
from unittest.mock import patch, MagicMock, call
from pathlib import Path
import os
import json

from app.core.plugin import AnalysisResult, Issue, Severity
from app.plugins.codeql_plugin import CodeQLPlugin

# Mock the Console for cleaner test output
@pytest.fixture(autouse=True)
def mock_console_print():
    with patch('app.plugins.codeql_plugin.console.print') as mock_print:
        yield mock_print

# Fixture for a dummy source root
@pytest.pytest.fixture
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
    mock_subprocess_run.side_effect = [
        # First call (database create) fails
        pytest.raises(subprocess.CalledProcessError, lambda: mock_subprocess_run.return_value.__init__(returncode=1, stderr="DB Error")),
        MagicMock(returncode=0) # Second call (analyze) would succeed if reached
    ]
    mock_subprocess_run.return_value = MagicMock(returncode=1, stderr="DB creation failed") # For the first call only
    
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

```

### Étape 3 : Créer le fichier `tests/security/test_secret_scanner.py`

Créez un fichier nommé `test_secret_scanner.py` dans le répertoire `tests/security/` et copiez-y le contenu suivant :

```python
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
    scanner = SecretScanner(entropy_threshold=4.0) # Lower threshold for test
    issues = scanner.scan_file(dummy_file_path)
    assert len(issues) == 1
    assert "haute entropie" in issues[0].message
    assert issues[0].severity == Severity.HIGH

def test_scan_file_common_pattern_api_key(dummy_file_path):
    scanner = SecretScanner(common_secret_patterns={"test_key": r"API_KEY\s*=\s*['"](?P<secret>ghp_[\w]{36})['"]"})
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
    scanner = SecretScanner(common_secret_patterns={"api_key": r"API_KEY\s*=\s*['"](?P<secret>[\w]+)['"]"})
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
    
    scanner = SecretScanner(common_secret_patterns={"api_key": r"API_KEY\s*=\s*['"](?P<secret>[\w]+)['"]"})
    result = scanner.scan_paths([tmp_path]) # Scan from root tmp_path
    assert len(result.issues) == 1
    assert f1.relative_to(Path.cwd()).as_posix() in result.issues[0].file # Check relative path

def test_scan_paths_with_exclude(tmp_path):
    f1 = tmp_path / "f1.py"
    f1.write_text("API_KEY = 'secret'")
    f2 = tmp_path / "ignored.py"
    f2.write_text("API_KEY = 'secret'")
    
    scanner = SecretScanner(common_secret_patterns={"api_key": r"API_KEY\s*=\s*['"](?P<secret>[\w]+)['"]"}, exclude_patterns=["ignored.py"])
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

```

### Étape 4 : Créer le fichier `tests/security/test_taint_analyzer.py`

Créez un fichier nommé `test_taint_analyzer.py` dans le répertoire `tests/security/` et copiez-y le contenu suivant :

```python
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import re

from app.core.plugin import AnalysisResult, Issue, Severity
from app.security.taint_analyzer import TaintAnalyzer, analyze_taint

# Mock console print
@pytest.fixture(autouse=True)
def mock_console_print():
    with patch('app.security.taint_analyzer.console.print') as mock_print:
        yield mock_print

# Fixture for a dummy file path
@pytest.fixture
def dummy_file_path(tmp_path):
    f = tmp_path / "main.py"
    return f

# --- Tests for TaintAnalyzer ---
def test_taint_analyzer_init():
    analyzer = TaintAnalyzer(
        sensitive_patterns=["GDPR", "PII"],
        entry_points=["input", "request"],
        sinks=["db_query", "log_data"]
    )
    assert len(analyzer.sensitive_regexes) == 2
    assert "GDPR" in analyzer.sensitive_patterns

def test_is_sensitive_data():
    analyzer = TaintAnalyzer(sensitive_patterns=["GDPR", "PII"], entry_points=[], sinks=[])
    assert analyzer._is_sensitive_data("user_data = get_gdpr_info()") is True
    assert analyzer._is_sensitive_data("safe_data = calculate_sum()") is False

def test_is_entry_point():
    analyzer = TaintAnalyzer(sensitive_patterns=[], entry_points=["main.py", "user_input"], sinks=[])
    assert analyzer._is_entry_point(Path("src/main.py"), "data = user_input()") is True
    assert analyzer._is_entry_point(Path("src/utils.py"), "data = clean_data()") is False

def test_is_sink():
    analyzer = TaintAnalyzer(sensitive_patterns=[], entry_points=[], sinks=["db_query", "log_data"])
    assert analyzer._is_sink("execute(db_query)") is True
    assert analyzer._is_sink("print('hello')") is False

def test_analyze_file_no_taint(dummy_file_path):
    dummy_file_path.write_text("safe_data = 1\nresult = safe_data * 2")
    analyzer = TaintAnalyzer(
        sensitive_patterns=["GDPR"], entry_points=["main.py"], sinks=["db_query"]
    )
    issues = analyzer.analyze_file(dummy_file_path)
    assert len(issues) == 0

def test_analyze_file_with_taint_flow(dummy_file_path):
    dummy_file_path.write_text(
        "user_input = request.get_data()\n"
        "gdpr_data = user_input.get('GDPR')\n"
        "db_query(gdpr_data)"
    )
    analyzer = TaintAnalyzer(
        sensitive_patterns=["GDPR"], 
        entry_points=["request.get_data", "main.py"], # main.py as entry for file
        sinks=["db_query"]
    )
    issues = analyzer.analyze_file(dummy_file_path)
    assert len(issues) == 1
    assert "Potentiel flux de données sensibles vers un sink détecté" in issues[0].message
    assert issues[0].severity == Severity.CRITICAL
    assert issues[0].line == 3 # Line where sink is detected

def test_analyze_file_no_entry_point_in_file(dummy_file_path):
    dummy_file_path.write_text("gdpr_data = 'sensitive'\ndb_query(gdpr_data)")
    analyzer = TaintAnalyzer(
        sensitive_patterns=["gdpr"], entry_points=["other_entry.py"], sinks=["db_query"]
    )
    issues = analyzer.analyze_file(dummy_file_path)
    assert len(issues) == 0 # Should not analyze if file is not an entry point

def test_analyze_paths_directory_with_taint(tmp_path):
    main_file = tmp_path / "main.py"
    main_file.write_text(
        "user_input = request.get_data()\n"
        "gdpr_data = user_input.get('GDPR')\n"
        "db_query(gdpr_data)"
    )
    utils_file = tmp_path / "utils.py"
    utils_file.write_text("safe_func()")

    analyzer = TaintAnalyzer(
        sensitive_patterns=["GDPR"], 
        entry_points=["main.py", "request.get_data"], 
        sinks=["db_query"]
    )
    result = analyzer.analyze_paths([tmp_path])
    assert len(result.issues) == 1
    assert "main.py" in result.issues[0].file

# --- Tests for analyze_taint convenience function ---
def test_analyze_taint_convenience(tmp_path):
    f1 = tmp_path / "api.py"
    f1.write_text(
        "user_input = get_request()\n"
        "pii_data = user_input['PII']\n"
        "log_to_db(pii_data)"
    )
    
    result = analyze_taint(
        paths=[f1],
        sensitive_patterns=["PII"],
        entry_points=["api.py", "get_request"],
        sinks=["log_to_db"]
    )
    assert len(result.issues) == 1
```