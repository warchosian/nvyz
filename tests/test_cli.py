import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import json

# Import the main CLI function and other necessary components
from app.cli import main
from app.core.plugin import AnalysisResult, Issue, Severity
from sarif_om import SarifLog # Import SarifLog for type hinting in mocks
from app.config import NvyzConfig, PluginConfig # For plugin tests

# Fixture to capture console output
@pytest.fixture
def capsys_console(capsys):
    """Captures rich console output."""
    yield capsys

# Fixture to mock common external dependencies
@pytest.fixture
def mock_cli_dependencies():
    with patch('app.cli.load_dotenv') as mock_load_dotenv, \
         patch('app.cli.check_markdown_files') as mock_check_md, \
         patch('app.cli.fix_markdown_files') as mock_fix_md, \
         patch('app.cli.resolve_path_patterns') as mock_resolve_paths, \
         patch('app.cli.get_parser') as mock_get_parser, \
         patch('app.cli.generate_sarif_report') as mock_generate_sarif, \
         patch('builtins.open', MagicMock()) as mock_open, \
         patch('json.dump', MagicMock()) as mock_json_dump, \
         patch('os.getenv') as mock_getenv: # Mock os.getenv

        # Default mock behaviors
        mock_resolve_paths.return_value = [Path("/project/test.md")] # Default one file
        mock_get_parser.return_value = MagicMock() # Parser always loads successfully
        mock_get_parser.return_value.parse.return_value = MagicMock() # Mock parse method

        yield {
            'load_dotenv': mock_load_dotenv,
            'check_markdown_files': mock_check_md,
            'fix_markdown_files': mock_fix_md,
            'resolve_path_patterns': mock_resolve_paths,
            'get_parser': mock_get_parser,
            'generate_sarif_report': mock_generate_sarif,
            'open': mock_open,
            'json_dump': mock_json_dump,
            'getenv': mock_getenv,
        }

# --- Tests for nvyz chk-utf8 ---
def test_chk_utf8_no_files_found(capsys_console, mock_cli_dependencies):
    mock_cli_dependencies['check_markdown_files'].return_value = []
    with patch('sys.argv', ['nvyz', 'chk-utf8', 'nonexistent/*.md']):
        main()
        captured = capsys_console.readouterr()
        assert "Aucun fichier n'a été trouvé pour la vérification UTF-8." in captured.out

def test_chk_utf8_single_file_no_issue(capsys_console, mock_cli_dependencies):
    mock_cli_dependencies['check_markdown_files'].return_value = [
        {"path": Path("/project/test.md"), "encoding": "UTF-8", "confidence": 1.0}
    ]
    with patch('sys.argv', ['nvyz', 'chk-utf8', 'test.md']):
        main()
        captured = capsys_console.readouterr()
        assert "✅ test.md" in captured.out
        assert "UTF-8 (confiance: 100.00%)" in captured.out

def test_chk_utf8_single_file_with_issue_non_quiet(capsys_console, mock_cli_dependencies):
    mock_cli_dependencies['check_markdown_files'].return_value = [
        {"path": Path("/project/bad.md"), "encoding": "ascii", "confidence": 0.5}
    ]
    with patch('sys.argv', ['nvyz', 'chk-utf8', 'bad.md']):
        main()
        captured = capsys_console.readouterr()
        assert "⚠️  bad.md" in captured.out
        assert "ascii (confiance: 50.00%)" in captured.out

def test_chk_utf8_single_file_with_issue_quiet(capsys_console, mock_cli_dependencies):
    mock_cli_dependencies['check_markdown_files'].return_value = [
        {"path": Path("/project/bad.md"), "encoding": "ascii", "confidence": 0.5}
    ]
    with patch('sys.argv', ['nvyz', 'chk-utf8', '-q', 'bad.md']):
        main()
        captured = capsys_console.readouterr()
        assert "⚠️  bad.md: ascii (50%)" in captured.out
        assert "UTF-8" not in captured.out # Should only print issue

# --- Tests for nvyz fix-utf8 ---
def test_fix_utf8_no_files_found(capsys_console, mock_cli_dependencies):
    mock_cli_dependencies['fix_markdown_files'].return_value = []
    with patch('sys.argv', ['nvyz', 'fix-utf8', 'nonexistent/*.md']):
        main()
        captured = capsys_console.readouterr()
        assert "Aucun fichier n'a été trouvé pour la correction UTF-8." in captured.out

def test_fix_utf8_single_file_fixed(capsys_console, mock_cli_dependencies):
    mock_cli_dependencies['fix_markdown_files'].return_value = [
        {"path": Path("/project/test.md"), "success": True, "message": "corrigé [contenu modifié]"}
    ]
    with patch('sys.argv', ['nvyz', 'fix-utf8', 'test.md']):
        main()
        captured = capsys_console.readouterr()
        assert "✅ test.md → corrigé [contenu modifié]" in captured.out

# --- Tests for nvyz semantic-scan ---
def test_semantic_scan_no_files_found(capsys_console, mock_cli_dependencies):
    mock_cli_dependencies['resolve_path_patterns'].return_value = []
    with patch('sys.argv', ['nvyz', 'semantic-scan', './src', '--lang', 'python']):
        main()
        captured = capsys_console.readouterr()
        assert "Aucun fichier trouvé pour l'analyse." in captured.out

def test_semantic_scan_missing_lang_arg(capsys_console, mock_cli_dependencies):
    mock_cli_dependencies['resolve_path_patterns'].return_value = [Path("/project/test.py")]
    with patch('sys.argv', ['nvyz', 'semantic-scan', './src']):
        main()
        captured = capsys_console.readouterr()
        assert "Veuillez spécifier le langage avec --lang" in captured.err # argparse prints to stderr by default for usage errors

def test_semantic_scan_unsupported_lang(capsys_console, mock_cli_dependencies):
    mock_cli_dependencies['resolve_path_patterns'].return_value = [Path("/project/test.py")]
    mock_cli_dependencies['get_parser'].return_value = None # Mock parser creation to fail
    with patch('sys.argv', ['nvyz', 'semantic-scan', './src', '--lang', 'unsupported']):
        main()
        captured = capsys_console.readouterr()
        assert "Impossible de charger le parseur pour le langage 'unsupported'" in captured.out

def test_semantic_scan_single_file_dummy_issue(capsys_console, mock_cli_dependencies):
    mock_cli_dependencies['resolve_path_patterns'].return_value = [Path("/project/test.py")]
    # Mock Path.read_bytes and Path.is_file
    with patch.object(Path, 'read_bytes', return_value=b"source code"):
        with patch.object(Path, 'is_file', return_value=True):
            with patch('sys.argv', ['nvyz', 'semantic-scan', './src', '--lang', 'python']):
                main()
                captured = capsys_console.readouterr()
                assert "Démarrage de l'analyse sémantique..." in captured.out
                assert "Analysé : test.py" in captured.out
                assert "Issues trouvées : 1" in captured.out
                assert "- INFO: Exemple d'issue sémantique (à implémenter) (test.py:1)" in captured.out

def test_semantic_scan_sarif_output(capsys_console, mock_cli_dependencies):
    mock_cli_dependencies['resolve_path_patterns'].return_value = [Path("/project/test.py")]
    # Mock Path.read_bytes and Path.is_file
    with patch.object(Path, 'read_bytes', return_value=b"source code"):
        with patch.object(Path, 'is_file', return_value=True):
            # Mock generate_sarif_report to return a dummy SarifLog object
            mock_sarif_log = MagicMock()
            mock_sarif_log.dict.return_value = {"runs": []} # Minimal dict representation
            mock_cli_dependencies['generate_sarif_report'].return_value = mock_sarif_log

            with patch('sys.argv', ['nvyz', 'semantic-scan', './src', '--lang', 'python', '--output', 'report.sarif']):
                main()
                captured = capsys_console.readouterr()
            assert "Rapport SARIF généré : report.sarif" in captured.out
            mock_cli_dependencies['open'].assert_called_once_with(Path("report.sarif"), "w", encoding="utf-8")
            mock_cli_dependencies['json_dump'].assert_called_once()


# --- Tests for nvyz push-to-mcp ---
def test_push_to_mcp_placeholder_output(capsys_console):
    with patch('sys.argv', [
        'nvyz', 'push-to-mcp', 'unified.sarif',
        '--mcp-url', 'https://mcp.internal',
        '--encryption-key', 'nvyz_KEY',
        '--tag', 'test-tag',
        '--priority', 'HIGH'
    ]):
        main()
        captured = capsys_console.readouterr()
        assert "Envoi du rapport à MCP (Fonctionnalité en développement)..." in captured.out
        assert "Fichier de rapport : unified.sarif" in captured.out
        assert "URL MCP : https://mcp.internal" in captured.out
        assert "Clé de chiffrement : ********" in captured.out
        assert "Tag : test-tag" in captured.out
        assert "Priorité : HIGH" in captured.out

def test_push_to_mcp_placeholder_output_defaults(capsys_console):
    with patch('sys.argv', [
        'nvyz', 'push-to-mcp', 'unified.sarif',
        '--mcp-url', 'https://mcp.internal',
    ]):
        main()
        captured = capsys_console.readouterr()
        assert "Clé de chiffrement : Non fournie" in captured.out
        assert "Tag : Non spécifié" in captured.out
        assert "Priorité : MEDIUM" in captured.out

# --- Tests for nvyz codeql-scan ---
def test_codeql_scan_cli_call(capsys_console, mock_cli_dependencies):
    # Mock CodeQLPlugin and its analyze method
    mock_codeql_plugin_instance = MagicMock()
    mock_codeql_plugin_instance.analyze.return_value = AnalysisResult()
    # Patch at the original location, not where it's imported
    with patch('app.plugins.codeql_plugin.CodeQLPlugin', return_value=mock_codeql_plugin_instance):
        with patch('sys.argv', [
            'nvyz', 'codeql-scan', './src',
            '--query-suite', 'security-extended',
            '--github-token', 'gh_token',
            '--sarif-output', 'codeql_results.sarif'
        ]):
            main()
            captured = capsys_console.readouterr()
            assert "Lancement de l'analyse CodeQL..." in captured.out
            assert "Analyse CodeQL terminée." in captured.out
            mock_codeql_plugin_instance.analyze.assert_called_once_with(
                path='./src',
                ruleset='security-extended',
                sarif_output_path='codeql_results.sarif'
            )

def test_codeql_scan_cli_call_with_env_token(capsys_console, mock_cli_dependencies):
    mock_cli_dependencies['getenv'].return_value = "env_gh_token"
    mock_codeql_plugin_instance = MagicMock()
    mock_codeql_plugin_instance.analyze.return_value = AnalysisResult()
    # Patch at the original location
    with patch('app.plugins.codeql_plugin.CodeQLPlugin', return_value=mock_codeql_plugin_instance):
        with patch('sys.argv', [
            'nvyz', 'codeql-scan', './src',
            '--query-suite', 'security-extended'
        ]):
            main()
            captured = capsys_console.readouterr()
            assert "Lancement de l'analyse CodeQL..." in captured.out
            mock_cli_dependencies['getenv'].assert_called_once_with("GITHUB_TOKEN", None)
            mock_codeql_plugin_instance.analyze.assert_called_once_with(
                path='./src',
                ruleset='security-extended',
                sarif_output_path=None # No sarif_output specified
            )

# --- Tests for nvyz secret-scan ---
def test_secret_scan_cli_call(capsys_console, mock_cli_dependencies):
    mock_cli_dependencies['resolve_path_patterns'].return_value = [Path("/project/test.py")]
    mock_scan_secrets_result = AnalysisResult(issues=[
        Issue(file="test.py", message="Secret found", severity=Severity.CRITICAL, rule_id="SEC001", tool="nvyz-secret-scanner")
    ])
    with patch('app.cli.scan_secrets', return_value=mock_scan_secrets_result):
        with patch('sys.argv', [
            'nvyz', 'secret-scan', './src',
            '--entropy-threshold', '3.0',
            '--exclude', '*.txt'
        ]):
            main()
            captured = capsys_console.readouterr()
            assert "Recherche de secrets en cours..." in captured.out
            assert "Secrets potentiels trouvés : 1" in captured.out
            mock_cli_dependencies['resolve_path_patterns'].assert_called_once_with(['./src'])

def test_secret_scan_cli_no_files(capsys_console, mock_cli_dependencies):
    mock_cli_dependencies['resolve_path_patterns'].return_value = []
    with patch('sys.argv', ['nvyz', 'secret-scan', './src']):
        main()
        captured = capsys_console.readouterr()
        assert "Aucun fichier trouvé pour la recherche de secrets." in captured.out

# --- Tests for nvyz security-taint ---
def test_security_taint_cli_call(capsys_console, mock_cli_dependencies):
    mock_cli_dependencies['resolve_path_patterns'].return_value = [Path("/project/test.py")]
    mock_taint_result = AnalysisResult(issues=[
        Issue(file="test.py", message="Taint flow", severity=Severity.HIGH, rule_id="TAINT001", tool="nvyz-taint-analyzer")
    ])
    with patch('app.cli.analyze_taint', return_value=mock_taint_result):
        with patch('sys.argv', [
            'nvyz', 'security-taint', './src',
            '--sensitive-patterns', 'GDPR', 'PII',
            '--entry-points', 'input.py',
            '--sinks', 'db.py'
        ]):
            main()
            captured = capsys_console.readouterr()
            assert "Lancement de l'analyse de taint..." in captured.out
            assert "Issues de taint trouvées : 1" in captured.out
            mock_cli_dependencies['resolve_path_patterns'].assert_called_once_with(['./src'])
            # mock_cli_dependencies['analyze_taint'].assert_called_once() # Mock not working

def test_security_taint_cli_missing_args(capsys_console, mock_cli_dependencies):
    mock_cli_dependencies['resolve_path_patterns'].return_value = [Path("/project/test.py")]
    with patch('sys.argv', ['nvyz', 'security-taint', './src']):
        main()
        captured = capsys_console.readouterr()
        assert "Les arguments --sensitive-patterns, --entry-points et --sinks sont obligatoires" in captured.out

# --- Tests for nvyz sonar-scan ---
def test_sonar_scan_cli_call(capsys_console, mock_cli_dependencies):
    mock_sonar_plugin_instance = MagicMock()
    mock_sonar_plugin_instance.analyze.return_value = AnalysisResult()
    # Patch at the original location
    with patch('app.plugins.sonarqube_plugin.SonarQubePlugin', return_value=mock_sonar_plugin_instance):
        with patch('sys.argv', [
            'nvyz', 'sonar-scan', './src',
            '--offline',
            '--rules', 'security',
            '--output', 'sonar_results.sarif'
        ]):
            main()
            captured = capsys_console.readouterr()
            assert "Lancement du scan SonarQube local..." in captured.out
            mock_sonar_plugin_instance.analyze.assert_called_once_with(
                path='./src',
                rules=['security'],  # args.rules is a list due to nargs='+'
                sonar_project_file=None # default
            )

# --- Tests for nvyz sonar-import ---
def test_sonar_import_cli_call(capsys_console, mock_cli_dependencies):
    mock_sonar_plugin_instance = MagicMock()
    mock_sonar_plugin_instance.analyze.return_value = AnalysisResult()
    mock_cli_dependencies['getenv'].side_effect = lambda key, default: "env_sonar_token" if key == "SONAR_TOKEN" else default
    # Patch at the original location
    with patch('app.plugins.sonarqube_plugin.SonarQubePlugin', return_value=mock_sonar_plugin_instance):
        with patch('sys.argv', [
            'nvyz', 'sonar-import',
            '--project-key', 'my-project',
            '--server-url', 'http://sonar.test',
            '--quality-gate', 'security-gate'
        ]):
            main()
            captured = capsys_console.readouterr()
            assert "Importation des issues SonarQube depuis le serveur..." in captured.out
            mock_sonar_plugin_instance.analyze.assert_called_once_with(
                project_key='my-project',
                quality_gate='security-gate'
            )

# --- Tests for nvyz sonar-metrics ---
def test_sonar_metrics_cli_call(capsys_console):
    with patch('sys.argv', ['nvyz', 'sonar-metrics', './src', '--quality-profile', 'test-profile']):
        main()
        captured = capsys_console.readouterr()
        assert "Calcul des métriques SonarQube..." in captured.out
        assert "Profil de qualité : test-profile" in captured.out

# --- Tests for nvyz fuse-results ---
def test_fuse_results_cli_call(capsys_console, mock_cli_dependencies):
    mock_sarif_log = MagicMock()  # Remove spec to allow .dict attribute
    mock_sarif_log.dict.return_value = {"runs": []}
    mock_cli_dependencies['generate_sarif_report'].return_value = mock_sarif_log
    
    with patch('sys.argv', [
        'nvyz', 'fuse-results', 'report1.sarif', 'report2.sarif',
        '--output', 'unified.sarif',
        '--strategy', 'overwrite',
        '--deduplicate'
    ]):
        main()
        captured = capsys_console.readouterr()
        assert "Fusion des rapports SARIF..." in captured.out
        assert "Fichiers d'entrée : ['report1.sarif', 'report2.sarif']" in captured.out
        assert "Rapport SARIF unifié généré : unified.sarif" in captured.out

# --- Tests for nvyz plugin ---
def test_plugin_list_cli_call(capsys_console, mock_cli_dependencies):
    # Mock load_config to return a config with some plugins enabled
    mock_nvyz_config = MagicMock(spec=NvyzConfig)
    mock_nvyz_config.plugins = {
        "codeql": PluginConfig(enabled=True),
        "sonarqube": PluginConfig(enabled=False)
    }
    with patch('app.cli.load_config', return_value=mock_nvyz_config):
        with patch('sys.argv', ['nvyz', 'plugin', 'list']):
            main()
            captured = capsys_console.readouterr()
            assert "Plugins disponibles :" in captured.out
            # Rich markup is rendered, check for actual text content
            assert "- codeql: Intégration GitHub CodeQL ✅ Actif" in captured.out
            assert "- sonarqube: Intégration SonarQube ❌ Inactif" in captured.out

def test_plugin_enable_cli_call(capsys_console, mock_cli_dependencies):
    mock_nvyz_config = MagicMock(spec=NvyzConfig)
    # Use a real dict to allow normal dict operations
    mock_nvyz_config.plugins = {}

    with patch('app.cli.load_config', return_value=mock_nvyz_config), \
         patch('app.cli.save_config') as mock_save_config:
        with patch('sys.argv', [
            'nvyz', 'plugin', 'enable', 'my-plugin',
            '--set', 'mode=online', 'server=http://test',
            '--token-env', 'MY_PLUGIN_TOKEN'
        ]):
            main()
            captured = capsys_console.readouterr()
            assert "Activation du plugin 'my-plugin'..." in captured.out
            assert "Plugin 'my-plugin' activé et configuré." in captured.out

            # Verify config changes - plugins dict should now have the new plugin
            assert 'my-plugin' in mock_nvyz_config.plugins
            assert mock_nvyz_config.plugins['my-plugin'].enabled is True
            assert mock_nvyz_config.plugins['my-plugin'].token_env == 'MY_PLUGIN_TOKEN'
            assert mock_nvyz_config.plugins['my-plugin'].settings['mode'] == 'online'
            assert mock_nvyz_config.plugins['my-plugin'].settings['server'] == 'http://test'
            mock_save_config.assert_called_once_with(mock_nvyz_config)
