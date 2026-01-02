# Instructions pour la création des tests unitaires de la Phase 3 (Plugins SonarQube) et Phase 4 (Configuration)

Pour continuer, veuillez suivre les étapes suivantes pour créer les répertoires de tests et les fichiers de test correspondants.

### Étape 1 : Créer les répertoires de tests supplémentaires

Exécutez la commande suivante dans votre terminal, à la racine du projet `nvyz` :

```bash
mkdir -p tests/config
```

### Étape 2 : Créer le fichier `tests/plugins/test_sonarqube_plugin.py`

Créez un fichier nommé `test_sonarqube_plugin.py` dans le répertoire `tests/plugins/` et copiez-y le contenu suivant :

```python
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import subprocess
import json
import os

from app.core.plugin import AnalysisResult, Issue, Severity
from app.plugins.sonarqube_plugin import SonarQubePlugin, SarifConverter

# Fixture to mock console print
@pytest.fixture(autouse=True)
def mock_console_print():
    with patch('app.plugins.sonarqube_plugin.console.print') as mock_print:
        yield mock_print

# Fixture to mock subprocess.run for sonar-scanner CLI checks
@pytest.fixture
def mock_subprocess_run():
    with patch('subprocess.run') as mock_run:
        # Default success for --version check
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Success",
            stderr=""
        )
        yield mock_run

# Fixture for a dummy source root
@pytest.fixture
def dummy_source_root(tmp_path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "main.py").write_text("print('hello')")
    return src_dir

# --- Tests for SonarQubePlugin ---
def test_sonarqube_plugin_init_offline_success(mock_subprocess_run):
    plugin = SonarQubePlugin(mode="offline")
    assert plugin.mode == "offline"
    mock_subprocess_run.assert_called_once_with(["sonar-scanner", "--version"], capture_output=True, check=True)

def test_sonarqube_plugin_init_offline_no_cli_raises_runtime_error():
    with patch('subprocess.run', side_effect=FileNotFoundError):
        with pytest.raises(RuntimeError, match="SonarScanner CLI not found"):
            SonarQubePlugin(mode="offline")

def test_sonarqube_plugin_init_online_success():
    plugin = SonarQubePlugin(mode="online", server_url="http://sonar.test", token="test_token")
    assert plugin.mode == "online"
    assert plugin.server_url == "http://sonar.test"
    assert plugin.token == "test_token"

def test_sonarqube_plugin_init_online_missing_args_raises_value_error():
    with pytest.raises(ValueError, match="Server URL and token are required"):
        SonarQubePlugin(mode="online", server_url="http://sonar.test")
    with pytest.raises(ValueError, match="Server URL and token are required"):
        SonarQubePlugin(mode="online", token="test_token")

def test_sonarqube_plugin_analyze_offline_success(dummy_source_root, mock_subprocess_run):
    # Mock open and json.load for SARIF report
    mock_sarif_content = {"issues": [{"message": "Test issue"}]} # Simplified for SarifConverter dummy
    with patch('builtins.open', MagicMock()), \
         patch('json.load', return_value=mock_sarif_content):
        
        plugin = SonarQubePlugin(mode="offline")
        result = plugin.analyze(path=str(dummy_source_root))

        assert isinstance(result, AnalysisResult)
        assert len(result.issues) == 1 # From dummy converter
        mock_subprocess_run.assert_called_with(
            ['sonar-scanner', f'-Dsonar.projectBaseDir={dummy_source_root}', f'-Dproject.settings={dummy_source_root / "sonar-project.properties"}', '-Dsonar.scm.disabled=true', f'-Dsonar.report.export.path={dummy_source_root / "sonar-report.json"}'],
            check=True, capture_output=True, text=True
        )

def test_sonarqube_plugin_analyze_online_success(mock_subprocess_run):
    with patch('requests.get') as mock_requests_get:
        # Mock requests.get response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "issues": [
                {"key": "issue1", "message": "API issue", "severity": "CRITICAL", "component": "src/file.js", "line": 1}
            ]
        }
        mock_requests_get.return_value = mock_response

        # Need a dummy convert_sonar_to_nvyz for testing analyze method.
        # sarif_generator.py has the real one, but sonarqube_plugin.py has a dummy for now.
        # This test will rely on the dummy converter in sonarqube_plugin.py
        
        plugin = SonarQubePlugin(mode="online", server_url="http://sonar.test", token="test_token")
        result = plugin.analyze(project_key="my-project")

        assert isinstance(result, AnalysisResult)
        assert len(result.issues) == 1 # From dummy converter
        assert "API issue" in result.issues[0].message
        mock_requests_get.assert_called_once() # Check that API was called

def test_sonarqube_plugin_analyze_offline_cli_failure(dummy_source_root, mock_subprocess_run):
    mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, "sonar-scanner", stderr="CLI failed")
    
    plugin = SonarQubePlugin(mode="offline")
    result = plugin.analyze(path=str(dummy_source_root))
    
    assert isinstance(result, AnalysisResult)
    assert len(result.issues) == 1
    assert "SonarScanner failed" in result.issues[0].message
    assert result.issues[0].severity == Severity.CRITICAL

# --- Tests for SarifConverter (dummy in plugin for now) ---
def test_dummy_sarif_converter_convert_sonar_to_nvyz():
    sonar_report_with_issue = {"issues": [{"message": "Test issue"}]}
    result = SarifConverter.convert_sonar_to_nvyz(sonar_report_with_issue)
    assert len(result.issues) == 1
    assert "Dummy issue from SonarQube" in result.issues[0].message

    sonar_report_no_issue = {}
    result = SarifConverter.convert_sonar_to_nvyz(sonar_report_no_issue)
    assert len(result.issues) == 0
```

### Étape 3 : Créer le fichier `tests/config/test_config.py`

Créez un fichier nommé `test_config.py` dans le répertoire `tests/config/` et copiez-y le contenu suivant :

```python
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import os
import yaml

from app.config import NvyzConfig, PluginConfig, get_config_path, load_config, save_config, DEFAULT_CONFIG

# Fixture to mock os.getenv for config path
@pytest.fixture(autouse=True)
def mock_os_getenv(monkeypatch):
    # Mock APPDATA for Windows, XDG_CONFIG_HOME for Linux/macOS
    monkeypatch.setenv("APPDATA", str(Path("/mocked/appdata")))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(Path("/mocked/xdg_config")))
    yield

# Fixture for a temporary config path
@pytest.fixture
def temp_config_path(tmp_path, monkeypatch):
    mock_config_dir = tmp_path / "nvyz_config"
    mock_config_dir.mkdir()
    monkeypatch.setattr(Path, 'home', lambda: tmp_path) # Mock home for cross-platform
    
    # Patch get_config_path to return our temporary path
    with patch('app.config.get_config_path', return_value=mock_config_dir / ".nvyzrc.yaml"):
        yield mock_config_dir / ".nvyzrc.yaml"

# --- Tests for NvyzConfig and PluginConfig models ---
def test_plugin_config_default():
    pc = PluginConfig()
    assert pc.enabled is False
    assert pc.mode is None
    assert pc.settings == {}

def test_plugin_config_custom():
    pc = PluginConfig(enabled=True, mode="online", settings={"server": "http://test"})
    assert pc.enabled is True
    assert pc.mode == "online"
    assert pc.settings["server"] == "http://test"

def test_nvyz_config_default():
    nc = NvyzConfig()
    assert nc.default_lang == "python"
    assert nc.parallel == 1
    assert nc.exclude_patterns == []
    assert nc.plugins == {}
    assert nc.analyzers == {}

def test_nvyz_config_custom():
    config_data = {
        "default_lang": "javascript",
        "plugins": {
            "codeql": {"enabled": True, "token_env": "GH_TOKEN"},
            "sonarqube": {"enabled": False, "mode": "offline"}
        },
        "analyzers": {
            "python": {"ruleset": "default"}
        }
    }
    nc = NvyzConfig(**config_data)
    assert nc.default_lang == "javascript"
    assert nc.plugins["codeql"].enabled is True
    assert nc.plugins["sonarqube"].mode == "offline"
    assert nc.analyzers["python"]["ruleset"] == "default"

def test_nvyz_config_validation_error():
    with pytest.raises(ValidationError):
        NvyzConfig(parallel="not_an_int")

# --- Tests for get_config_path ---
def test_get_config_path_windows(monkeypatch):
    monkeypatch.setattr(os, 'name', 'nt')
    path = get_config_path()
    assert "nvyz\\.nvyzrc.yaml" in str(path)
    assert Path(os.getenv("APPDATA")) in path.parents

def test_get_config_path_linux(monkeypatch):
    monkeypatch.setattr(os, 'name', 'posix')
    monkeypatch.setenv("XDG_CONFIG_HOME", "/home/user/.config")
    path = get_config_path()
    assert "/home/user/.config/nvyz/.nvyzrc.yaml" == str(path)

# --- Tests for load_config and save_config ---
def test_load_config_default(temp_config_path):
    # Config file does not exist, should return default
    config = load_config()
    assert config == DEFAULT_CONFIG

def test_save_and_load_config(temp_config_path):
    config = NvyzConfig(default_lang="go", parallel=4)
    config.plugins["codeql"] = PluginConfig(enabled=True, token_env="CODEQL_TOKEN")
    save_config(config)

    # Verify file content
    with open(temp_config_path, "r") as f:
        content = f.read()
        assert "default_lang: go" in content
        assert "parallel: 4" in content
        assert "plugins:" in content
        assert "codeql:" in content
        assert "enabled: true" in content

    # Load and verify
    loaded_config = load_config()
    assert loaded_config.default_lang == "go"
    assert loaded_config.parallel == 4
    assert loaded_config.plugins["codeql"].enabled is True
    assert loaded_config.plugins["codeql"].token_env == "CODEQL_TOKEN"

def test_load_config_invalid_yaml(temp_config_path, capsys):
    temp_config_path.write_text("invalid_yaml: [") # Broken YAML
    config = load_config()
    assert config == DEFAULT_CONFIG # Should fallback to default
    captured = capsys.readouterr()
    assert "Error loading configuration" in captured.out

def test_load_config_invalid_pydantic_data(temp_config_path, capsys):
    config_data = {"parallel": "not_an_int"}
    with open(temp_config_path, "w") as f:
        yaml.dump(config_data, f)
    config = load_config()
    assert config == DEFAULT_CONFIG # Should fallback to default
    captured = capsys.readouterr()
    assert "Error loading configuration" in captured.out

def test_save_config_error(temp_config_path, capsys):
    # Simulate permission error by making parent dir read-only
    temp_config_path.parent.chmod(0o444)
    config = NvyzConfig()
    save_config(config)
    captured = capsys.readouterr()
    assert "Error saving configuration" in captured.out
```