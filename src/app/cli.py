"Module CLI pour nvyz."

import argparse
import sys
from pathlib import Path
from rich.console import Console
from dotenv import load_dotenv
import json # For writing SARIF
import os # For checking environment variables

from .core.pathglob import resolve_path_patterns
from .core.treesitter import get_parser
from .core.plugin import Issue, AnalysisResult, Severity

from .encoding.chk_utf8 import check_markdown_files
from .encoding.fix_utf8 import fix_markdown_files
from .reporting.sarif_generator import generate_sarif_report

# New imports for Phase 2 & 3
from .plugins.codeql_plugin import CodeQLPlugin
from .security.secret_scanner import scan_secrets
from .security.taint_analyzer import analyze_taint
from .plugins.sonarqube_plugin import SonarQubePlugin

# New import for Phase 4 (Config)
from .config import load_config, save_config, NvyzConfig, PluginConfig # New import


def safe_relative_path(path: Path) -> Path:
    """Convert path to relative if possible, otherwise return as-is."""
    try:
        return path.relative_to(Path.cwd())
    except (ValueError, TypeError):
        # If path is absolute or not under cwd, use just the filename or the path as-is
        return Path(path.name) if path.name else path


def main():
    """Fonction principale appelée par la commande `nvyz`."""
    load_dotenv() # Load environment variables from .env file
    console = Console()
    parser = argparse.ArgumentParser(description='nvyz CLI')
    subparsers = parser.add_subparsers(dest='command', help='Sous-commandes disponibles')

    # Commande chk-utf8
    parser_chk_utf8 = subparsers.add_parser('chk-utf8', help='Vérifie l\'encodage UTF-8 des fichiers Markdown')
    parser_chk_utf8.add_argument('files', nargs='+', help='Fichiers ou motifs (globs) à vérifier')
    parser_chk_utf8.add_argument('--quiet', '-q', action='store_true', help='Mode silencieux : n\'affiche que les problèmes')
    parser_chk_utf8.add_argument('--output', help='Chemin du fichier de sortie (txt ou md).')
    parser_chk_utf8.add_argument('--format', choices=['txt', 'md'], default='txt', help='Format du rapport (txt ou md).')

    # Commande fix-utf8
    parser_fix_utf8 = subparsers.add_parser('fix-utf8', help='Corrige l\'encodage UTF-8 et le contenu des fichiers Markdown')
    parser_fix_utf8.add_argument('files', nargs='+', help='Fichiers ou motifs (globs) à corriger')
    parser_fix_utf8.add_argument('--dry-run', '-n', action='store_true', help='Simuler sans modifier les fichiers')
    parser_fix_utf8.add_argument('--backup', action='store_true', help='Créer un .bak avant modification')

    # Commande semantic-scan
    parser_semantic_scan = subparsers.add_parser('semantic-scan', help='Effectue une analyse sémantique du code.')
    parser_semantic_scan.add_argument('path', nargs='+', help='Chemins ou motifs (globs) à analyser.')
    parser_semantic_scan.add_argument('--lang', help='Langage de programmation (ex: python, javascript).')
    parser_semantic_scan.add_argument('--auto-detect-lang', action='store_true', help='Détecte automatiquement le langage.')
    parser_semantic_scan.add_argument('--threshold', default='warning', help='Seuil de sévérité minimum pour les rapports (ex: info, warning, critical).')
    parser_semantic_scan.add_argument('--parallel', type=int, default=1, help='Nombre de processus parallèles à utiliser.')
    parser_semantic_scan.add_argument('--rules', nargs='+', help='Fichiers de règles personnalisées à utiliser.')
    parser_semantic_scan.add_argument('--exclude', nargs='+', help='Motifs (globs) de fichiers/répertoires à exclure.')
    parser_semantic_scan.add_argument('--output', help='Chemin du fichier de sortie (txt ou md).')
    parser_semantic_scan.add_argument('--format', choices=['txt', 'md'], default='txt', help='Format du rapport (txt ou md).')

    # Commande push-to-mcp
    parser_push_to_mcp = subparsers.add_parser('push-to-mcp', help='Envoie le rapport d\'analyse à la plateforme MCP.')
    parser_push_to_mcp.add_argument('report_file', help='Chemin vers le fichier de rapport SARIF unifié.')
    parser_push_to_mcp.add_argument('--mcp-url', required=True, help='URL de l\'API MCP.')
    parser_push_to_mcp.add_argument('--encryption-key', help='Clé de chiffrement pour le rapport (variable d\'environnement).')
    parser_push_to_mcp.add_argument('--tag', help='Tag pour identifier le rapport (ex: version, commit SHA).')
    parser_push_to_mcp.add_argument('--priority', default='MEDIUM', help='Priorité du rapport dans MCP (ex: LOW, MEDIUM, HIGH).')

    # Commande codeql-scan
    parser_codeql_scan = subparsers.add_parser('codeql-scan', help='Lance une analyse CodeQL sur le code source.')
    parser_codeql_scan.add_argument('path', nargs='+', help='Chemins ou motifs (globs) à analyser.')
    parser_codeql_scan.add_argument('--lang', '--language', help='Langage du projet (python, java, php, javascript, etc.). Si non spécifié, utilise la config.')
    parser_codeql_scan.add_argument('--query-suite', default='security', help='Suite de requêtes CodeQL à utiliser (ex: security, security-extended).')
    parser_codeql_scan.add_argument('--github-token', help='Token GitHub pour l\'accès à GitHub Advanced Security (variable d\'environnement).')
    parser_codeql_scan.add_argument('--sarif-output', help='Chemin du fichier de sortie SARIF pour les résultats CodeQL.')
    parser_codeql_scan.add_argument('--md-output', help='Chemin du fichier de sortie Markdown pour le résumé.')

    # Commande verify-codeql
    parser_verify_codeql = subparsers.add_parser('verify-codeql', help='Vérifie l\'installation et la configuration de CodeQL.')

    # Commande secret-scan
    parser_secret_scan = subparsers.add_parser('secret-scan', help='Détecte les secrets codés en dur dans le code.')
    parser_secret_scan.add_argument('path', nargs='+', help='Chemins ou motifs (globs) à analyser.')
    parser_secret_scan.add_argument('--entropy-threshold', type=float, default=4.5, help='Seuil d\'entropie pour la détection de secrets.')
    parser_secret_scan.add_argument('--exclude', nargs='+', help='Motifs (globs) de fichiers/répertoires à exclure.')
    parser_secret_scan.add_argument('--output', help='Chemin du fichier de sortie (txt ou md).')
    parser_secret_scan.add_argument('--format', choices=['txt', 'md'], default='txt', help='Format du rapport (txt ou md).')

    # Commande security-taint
    parser_security_taint = subparsers.add_parser('security-taint', help='Effectue une analyse de flux de données sensibles (taint analysis).')
    parser_security_taint.add_argument('path', nargs='+', help='Chemins ou motifs (globs) à analyser.')
    parser_security_taint.add_argument('--sensitive-patterns', nargs='+', help='Patterns de données sensibles à rechercher (ex: GDPR, PCI).')
    parser_security_taint.add_argument('--entry-points', nargs='+', help='Fichiers/fonctions considérés comme points d\'entrée des données.')
    parser_security_taint.add_argument('--sinks', nargs='+', help='Fichiers/fonctions considérés comme des sinks (où les données sensibles ne devraient pas arriver).')
    parser_security_taint.add_argument('--output', help='Chemin du fichier de sortie (txt ou md).')
    parser_security_taint.add_argument('--format', choices=['txt', 'md'], default='txt', help='Format du rapport (txt ou md).')

    # Commande sonar-scan
    parser_sonar_scan = subparsers.add_parser('sonar-scan', help='Exécute une analyse locale avec SonarScanner.')
    parser_sonar_scan.add_argument('path', nargs='+', help='Chemins ou motifs (globs) à analyser.')
    parser_sonar_scan.add_argument('--offline', action='store_true', help='Indique d\'exécuter SonarScanner en mode hors ligne.')
    parser_sonar_scan.add_argument('--rules', nargs='+', help='Ensemble de règles SonarQube à utiliser.')
    parser_sonar_scan.add_argument('--sonar-project-file', help='Chemin vers le fichier sonar-project.properties.')
    parser_sonar_scan.add_argument('--output', help='Chemin du fichier de sortie SARIF.')

    # Commande sonar-import
    parser_sonar_import = subparsers.add_parser('sonar-import', help='Importe les issues depuis un serveur SonarQube.')
    parser_sonar_import.add_argument('--project-key', required=True, help='Clé unique du projet SonarQube à importer.')
    parser_sonar_import.add_argument('--server-url', required=True, help='URL de base du serveur SonarQube.')
    parser_sonar_import.add_argument('--token', help='Token d\'authentification pour l\'accès à l\'API SonarQube.')
    parser_sonar_import.add_argument('--quality-gate', help='Nom de la Quality Gate SonarQube à évaluer.')
    parser_sonar_import.add_argument('--output', help='Chemin du fichier de sortie SARIF.')

    # Commande sonar-metrics
    parser_sonar_metrics = subparsers.add_parser('sonar-metrics', help='Calcule des métriques de dette technique et de qualité via SonarQube.')
    parser_sonar_metrics.add_argument('path', nargs='+', help='Chemins ou motifs (globs) à analyser.')
    parser_sonar_metrics.add_argument('--quality-profile', required=True, help='Nom du profil de qualité SonarQube à utiliser.')
    parser_sonar_metrics.add_argument('--output', help='Chemin du fichier de sortie CSV.')

    # Commande fuse-results
    parser_fuse_results = subparsers.add_parser('fuse-results', help='Fusionne plusieurs rapports SARIF en un seul rapport unifié.')
    parser_fuse_results.add_argument('input_files', nargs='+', help='Chemins vers les fichiers SARIF d\'entrée à fusionner.')
    parser_fuse_results.add_argument('--output', required=True, help='Chemin du fichier de sortie SARIF pour le rapport unifié.')
    parser_fuse_results.add_argument('--strategy', default='merge-conflicts', help='Stratégie de fusion en cas de conflits (ex: merge-conflicts, overwrite, keep-first).')
    parser_fuse_results.add_argument('--deduplicate', action='store_true', help='Déduplique les résultats identiques.')

    # Commande plugin
    parser_plugin = subparsers.add_parser('plugin', help='Gère les plugins de nvyz.')
    plugin_subparsers = parser_plugin.add_subparsers(dest='plugin_command', help='Commandes de gestion des plugins')

    # Commande plugin list
    parser_plugin_list = plugin_subparsers.add_parser('list', help='Liste les plugins disponibles et leur statut.')

    # Commande plugin enable
    parser_plugin_enable = plugin_subparsers.add_parser('enable', help='Active un plugin.')
    parser_plugin_enable.add_argument('plugin_name', help='Nom du plugin à activer (ex: codeql, sonarqube).')
    parser_plugin_enable.add_argument('--set', nargs='+', help='Définir des paramètres pour le plugin (clé=valeur).')
    parser_plugin_enable.add_argument('--token-env', help='Nom de la variable d\'environnement pour le token du plugin.')


    args = parser.parse_args()

    if args.command == 'chk-utf8':
        results = check_markdown_files(args.files)
        if not results:
            console.print("[yellow]Aucun fichier n'a été trouvé pour la vérification UTF-8.[/yellow]")
            return

        min_confidence = 0.7
        issues_count = 0
        ok_count = 0

        for res in results:
            encoding = res.get("encoding", "inconnu")
            confidence = res.get("confidence", 0.0)
            error = res.get("error")
            path_obj = Path(res.get("path", "Chemin inconnu"))
            try:
                path = str(path_obj.relative_to(Path.cwd()))
            except (ValueError, TypeError):
                # If relative_to fails, use just the filename
                path = path_obj.name if path_obj.name else str(path_obj)

            is_issue = error or (encoding and encoding.upper() not in ("UTF-8", "UTF8", "ASCII")) or confidence < min_confidence

            if is_issue:
                issues_count += 1
            else:
                ok_count += 1

            if not args.quiet:
                status_color = "green"
                status_icon = "[OK]"
                if error:
                    status_color = "red"
                    status_icon = "[ERREUR]"
                elif is_issue:
                    status_color = "yellow"
                    status_icon = "[WARNING]"

                console.print(f"[{status_color}]{status_icon}[/{status_color}] {path}", markup=False)
                if error:
                    console.print(f"    [red]Erreur: {error}[/red]", markup=False)
                else:
                    console.print(f"    Encodage: {encoding} (confiance: {confidence:.2%})", markup=False)
            elif is_issue:
                console.print(f"[yellow][WARNING] {path}: {encoding} ({confidence:.0%})[/yellow]", markup=False)

        # Write output file if specified
        if args.output:
            try:
                output_path = Path(args.output)
                format_type = args.format if args.format else ('md' if output_path.suffix == '.md' else 'txt')

                with open(output_path, 'w', encoding='utf-8') as f:
                    if format_type == 'md':
                        f.write('# Rapport de Vérification d\'Encodage UTF-8 - nvyz\n\n')
                        f.write(f'**Fichiers analysés:** {len(results)}\n\n')
                        f.write(f'**Fichiers conformes:** {ok_count} ({ok_count/len(results)*100:.1f}%)\n\n')
                        f.write(f'**Fichiers à corriger:** {issues_count} ({issues_count/len(results)*100:.1f}%)\n\n')

                        if issues_count > 0:
                            f.write('## ⚠️ Fichiers à corriger\n\n')
                            f.write('| Fichier | Encodage | Confiance | Statut |\n')
                            f.write('|---------|----------|-----------|--------|\n')
                            for res in results:
                                encoding = res.get("encoding", "inconnu")
                                confidence = res.get("confidence", 0.0)
                                error = res.get("error")
                                path_obj = Path(res.get("path", "Chemin inconnu"))
                                is_issue = error or (encoding and encoding.upper() not in ("UTF-8", "UTF8", "ASCII")) or confidence < min_confidence

                                if is_issue:
                                    status = "❌ ERREUR" if error else "⚠️ WARNING"
                                    f.write(f'| `{path_obj.name}` | {encoding} | {confidence:.0%} | {status} |\n')

                        if ok_count > 0:
                            f.write('\n## ✅ Fichiers conformes\n\n')
                            f.write(f'{ok_count} fichier(s) en UTF-8 avec confiance > {min_confidence:.0%}\n')
                    else:
                        f.write('='*80 + '\n')
                        f.write('RAPPORT DE VERIFICATION D\'ENCODAGE UTF-8 - nvyz\n')
                        f.write('='*80 + '\n\n')
                        f.write(f'Fichiers analyses: {len(results)}\n')
                        f.write(f'Fichiers conformes: {ok_count} ({ok_count/len(results)*100:.1f}%)\n')
                        f.write(f'Fichiers a corriger: {issues_count} ({issues_count/len(results)*100:.1f}%)\n\n')

                        if issues_count > 0:
                            f.write('FICHIERS A CORRIGER\n')
                            f.write('-'*80 + '\n')
                            for res in results:
                                encoding = res.get("encoding", "inconnu")
                                confidence = res.get("confidence", 0.0)
                                error = res.get("error")
                                path_obj = Path(res.get("path", "Chemin inconnu"))
                                is_issue = error or (encoding and encoding.upper() not in ("UTF-8", "UTF8", "ASCII")) or confidence < min_confidence

                                if is_issue:
                                    f.write(f'\nFichier: {path_obj}\n')
                                    f.write(f'  Encodage: {encoding}\n')
                                    f.write(f'  Confiance: {confidence:.0%}\n')
                                    if error:
                                        f.write(f'  Erreur: {error}\n')

                console.print(f"[green][OK] Rapport genere: {safe_relative_path(output_path)}[/green]", markup=False)
            except Exception as e:
                console.print(f"[red][ERREUR] Impossible d\'ecrire le rapport: {e}[/red]", markup=False)


    elif args.command == 'fix-utf8':
        results = fix_markdown_files(args.files, dry_run=args.dry_run, backup=args.backup)
        if not results:
            console.print("[yellow]Aucun fichier n'a été trouvé pour la correction UTF-8.[/yellow]")
            return
        
        for res in results:
            path_obj = Path(res.get("path", "Chemin inconnu"))
            try:
                path = str(path_obj.relative_to(Path.cwd()))
            except (ValueError, TypeError):
                # If relative_to fails, use just the filename
                path = path_obj.name if path_obj.name else str(path_obj)

            success = res.get("success", False)
            message = res.get("message", "Aucun message.")
            status_color = "green" if success else "red"
            icon = "[OK]" if success else "[ERREUR]"
            console.print(f"{icon} {path} - {message}", markup=False)
            
    elif args.command == 'semantic-scan':
        console.print("[blue]Demarrage de l\'analyse semantique...[/blue]", markup=False)

        all_paths = resolve_path_patterns(args.path)
        if not all_paths:
            console.print("[yellow][WARNING] Aucun fichier trouve pour l\'analyse.[/yellow]", markup=False)
            return

        # Placeholder for auto-detection logic based on file extension
        language = args.lang
        if not language:
            if args.auto_detect_lang:
                console.print("[red][ERREUR] L\'auto-detection du langage n\'est pas encore implementee. Veuillez specifier --lang.[/red]", markup=False)
                return
            else:
                console.print("[red]Veuillez specifier le langage avec --lang[/red]", markup=False)
                return

        console.print(f"[blue]Chargement du parser tree-sitter {language}...[/blue]", markup=False)
        parser = get_parser(language)
        if not parser:
            console.print(f"[red][ERREUR] Impossible de charger le parseur pour le langage '{language}'.[/red]", markup=False)
            console.print("[red]Verifier que tree-sitter est installe (pip install tree-sitter tree-sitter-python).[/red]", markup=False)
            return

        console.print("[green][OK] Parser charge[/green]", markup=False)

        # Helper function to analyze a single Python file
        def analyze_python_file(file_path, parser):
            """Analyse un fichier Python et retourne les issues detectees"""
            issues = []

            try:
                source_code = file_path.read_bytes()
                tree = parser.parse(source_code)

                # Analyse basique : detecter les fichiers trop longs
                lines = source_code.decode('utf-8', errors='ignore').split('\n')
                num_lines = len(lines)

                if num_lines > 500:
                    issues.append(Issue(
                        file=str(safe_relative_path(file_path)),
                        line=1,
                        message=f"Fichier tres long ({num_lines} lignes). Considerer de le diviser.",
                        severity=Severity.MEDIUM,
                        rule_id="N001-FILE-TOO-LONG",
                        tool="nvyz-semantic"
                    ))
                elif num_lines > 300:
                    issues.append(Issue(
                        file=str(safe_relative_path(file_path)),
                        line=1,
                        message=f"Fichier long ({num_lines} lignes). Surveiller la complexite.",
                        severity=Severity.LOW,
                        rule_id="N002-FILE-LONG",
                        tool="nvyz-semantic"
                    ))

                # Compter les fonctions (approximatif via tree-sitter)
                root = tree.root_node
                function_count = 0
                class_count = 0

                def count_nodes(node):
                    nonlocal function_count, class_count
                    if node.type == 'function_definition':
                        function_count += 1
                    elif node.type == 'class_definition':
                        class_count += 1
                    for child in node.children:
                        count_nodes(child)

                count_nodes(root)

                # Issue si trop de fonctions dans un fichier
                if function_count > 20:
                    issues.append(Issue(
                        file=str(safe_relative_path(file_path)),
                        line=1,
                        message=f"Nombreuses fonctions ({function_count}) dans un fichier. Considerer de le modulariser.",
                        severity=Severity.LOW,
                        rule_id="N003-MANY-FUNCTIONS",
                        tool="nvyz-semantic"
                    ))

            except Exception as e:
                issues.append(Issue(
                    file=str(safe_relative_path(file_path)),
                    line=1,
                    message=f"Erreur d\'analyse: {str(e)}",
                    severity=Severity.INFO,
                    rule_id="N999-PARSE-ERROR",
                    tool="nvyz-semantic"
                ))

            return issues

        # Helper function to analyze a single Java file
        def analyze_java_file(file_path, parser):
            """Analyse un fichier Java et retourne les issues detectees"""
            issues = []

            try:
                source_code = file_path.read_bytes()
                tree = parser.parse(source_code)

                # Analyse basique : detecter les fichiers trop longs
                lines = source_code.decode('utf-8', errors='ignore').split('\n')
                num_lines = len(lines)

                if num_lines > 600:
                    issues.append(Issue(
                        file=str(safe_relative_path(file_path)),
                        line=1,
                        message=f"Fichier tres long ({num_lines} lignes). Considerer de le diviser.",
                        severity=Severity.MEDIUM,
                        rule_id="N001-FILE-TOO-LONG",
                        tool="nvyz-semantic"
                    ))
                elif num_lines > 400:
                    issues.append(Issue(
                        file=str(safe_relative_path(file_path)),
                        line=1,
                        message=f"Fichier long ({num_lines} lignes). Surveiller la complexite.",
                        severity=Severity.LOW,
                        rule_id="N002-FILE-LONG",
                        tool="nvyz-semantic"
                    ))

                # Compter les methodes et classes (specific to Java node types)
                root = tree.root_node
                method_count = 0
                class_count = 0

                def count_nodes(node):
                    nonlocal method_count, class_count
                    if node.type == 'method_declaration':
                        method_count += 1
                    elif node.type == 'class_declaration':
                        class_count += 1
                    for child in node.children:
                        count_nodes(child)

                count_nodes(root)

                # Issue si trop de methodes dans un fichier
                if method_count > 25:
                    issues.append(Issue(
                        file=str(safe_relative_path(file_path)),
                        line=1,
                        message=f"Nombreuses methodes ({method_count}) dans un fichier. Considerer de le modulariser.",
                        severity=Severity.LOW,
                        rule_id="N003-MANY-METHODS",
                        tool="nvyz-semantic"
                    ))

            except Exception as e:
                issues.append(Issue(
                    file=str(safe_relative_path(file_path)),
                    line=1,
                    message=f"Erreur d\'analyse: {str(e)}",
                    severity=Severity.INFO,
                    rule_id="N999-PARSE-ERROR",
                    tool="nvyz-semantic"
                ))

            return issues

        # Helper function to analyze a single PHP file
        def analyze_php_file(file_path, parser):
            """Analyse un fichier PHP et retourne les issues detectees"""
            issues = []

            try:
                source_code = file_path.read_bytes()
                tree = parser.parse(source_code)

                # Analyse basique : detecter les fichiers trop longs
                lines = source_code.decode('utf-8', errors='ignore').split('\n')
                num_lines = len(lines)

                if num_lines > 600:
                    issues.append(Issue(
                        file=str(safe_relative_path(file_path)),
                        line=1,
                        message=f"Fichier tres long ({num_lines} lignes). Considerer de le diviser.",
                        severity=Severity.MEDIUM,
                        rule_id="N001-FILE-TOO-LONG",
                        tool="nvyz-semantic"
                    ))
                elif num_lines > 400:
                    issues.append(Issue(
                        file=str(safe_relative_path(file_path)),
                        line=1,
                        message=f"Fichier long ({num_lines} lignes). Surveiller la complexite.",
                        severity=Severity.LOW,
                        rule_id="N002-FILE-LONG",
                        tool="nvyz-semantic"
                    ))

                # Compter les fonctions et classes (specific to PHP node types)
                root = tree.root_node
                function_count = 0
                class_count = 0

                def count_nodes(node):
                    nonlocal function_count, class_count
                    if node.type in ('function_definition', 'method_declaration'):
                        function_count += 1
                    elif node.type == 'class_declaration':
                        class_count += 1
                    for child in node.children:
                        count_nodes(child)

                count_nodes(root)

                # Issue si trop de fonctions dans un fichier
                if function_count > 25:
                    issues.append(Issue(
                        file=str(safe_relative_path(file_path)),
                        line=1,
                        message=f"Nombreuses fonctions/methodes ({function_count}) dans un fichier. Considerer de le modulariser.",
                        severity=Severity.LOW,
                        rule_id="N003-MANY-FUNCTIONS",
                        tool="nvyz-semantic"
                    ))

            except Exception as e:
                issues.append(Issue(
                    file=str(safe_relative_path(file_path)),
                    line=1,
                    message=f"Erreur d\'analyse: {str(e)}",
                    severity=Severity.INFO,
                    rule_id="N999-PARSE-ERROR",
                    tool="nvyz-semantic"
                ))

            return issues

        analysis_results = AnalysisResult()
        console.print(f"[blue]Analyse en cours de {len(all_paths)} fichier(s)...[/blue]", markup=False)

        for idx, p in enumerate(all_paths, 1):
            if p.is_file():
                try:
                    console.print(f"  [{idx}/{len(all_paths)}] {safe_relative_path(p)}", markup=False)

                    # Analyze the file based on language
                    if language.lower() == 'python':
                        issues = analyze_python_file(p, parser)
                        analysis_results.issues.extend(issues)
                    elif language.lower() == 'java':
                        issues = analyze_java_file(p, parser)
                        analysis_results.issues.extend(issues)
                    elif language.lower() == 'php':
                        issues = analyze_php_file(p, parser)
                        analysis_results.issues.extend(issues)
                    else:
                        # For other languages, placeholder
                        console.print(f"[yellow][WARNING] Analyse semantique non implementee pour {language}[/yellow]", markup=False)

                except Exception as e:
                    console.print(f"[red][ERREUR] Erreur lors de l\'analyse de {safe_relative_path(p)}: {e}[/red]", markup=False)
            else:
                console.print(f"[yellow][WARNING] Ignore (n\'est pas un fichier) : {safe_relative_path(p)}[/yellow]", markup=False)

        console.print(f"\n[blue][OK] Analyse semantique terminee: {len(analysis_results.issues)} issue(s) detectee(s)[/blue]", markup=False)

        # Group by severity
        by_severity = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': [],
            'INFO': []
        }
        for issue in analysis_results.issues:
            severity_key = issue.severity.value
            by_severity[severity_key].append(issue)

        # Display summary
        console.print("\nRepartition par severite:", markup=False)
        console.print(f"  CRITICAL: {len(by_severity['CRITICAL'])}", markup=False)
        console.print(f"  HIGH:     {len(by_severity['HIGH'])}", markup=False)
        console.print(f"  MEDIUM:   {len(by_severity['MEDIUM'])}", markup=False)
        console.print(f"  LOW:      {len(by_severity['LOW'])}", markup=False)
        console.print(f"  INFO:     {len(by_severity['INFO'])}", markup=False)

        if analysis_results.issues:
            console.print(f"\n[bold red]Issues trouvees : {len(analysis_results.issues)}[/bold red]", markup=False)
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                issues = by_severity[severity]
                if issues:
                    console.print(f"\n--- {severity} ({len(issues)}) ---", markup=False)
                    for idx, issue in enumerate(issues[:10], 1):  # Limit to 10 per severity for console
                        console.print(f"  [{severity}-{idx}] {issue.rule_id}", markup=False)
                        console.print(f"    Fichier: {issue.file}", markup=False)
                        console.print(f"    Ligne: {issue.line}", markup=False)
                        console.print(f"    Message: {issue.message}", markup=False)
                    if len(issues) > 10:
                        console.print(f"    ... et {len(issues) - 10} autres issues {severity}", markup=False)
        else:
            console.print("\n[green][OK] Aucune issue semantique trouvee.[/green]", markup=False)

        if args.output:
            try:
                output_path = Path(args.output)

                # Generate text report
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write('='*80 + '\n')
                    f.write('RAPPORT D\'ANALYSE SEMANTIQUE - nvyz\n')
                    f.write('='*80 + '\n\n')
                    f.write(f'Fichiers analyses: {len(all_paths)}\n')
                    f.write(f'Issues detectees: {len(analysis_results.issues)}\n\n')

                    f.write('RESUME\n')
                    f.write('-'*80 + '\n')
                    f.write(f'CRITICAL: {len(by_severity["CRITICAL"])}\n')
                    f.write(f'HIGH:     {len(by_severity["HIGH"])}\n')
                    f.write(f'MEDIUM:   {len(by_severity["MEDIUM"])}\n')
                    f.write(f'LOW:      {len(by_severity["LOW"])}\n')
                    f.write(f'INFO:     {len(by_severity["INFO"])}\n\n')

                    if analysis_results.issues:
                        f.write('='*80 + '\n')
                        f.write('DETAILS DES ISSUES\n')
                        f.write('='*80 + '\n\n')

                        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                            issues = by_severity[severity]
                            if issues:
                                f.write(f'\n--- {severity} ({len(issues)}) ---\n\n')
                                for idx, issue in enumerate(issues, 1):
                                    f.write(f'[{severity}-{idx}] {issue.rule_id}\n')
                                    f.write(f'  Fichier: {issue.file}\n')
                                    f.write(f'  Ligne: {issue.line}\n')
                                    f.write(f'  Message: {issue.message}\n\n')
                    else:
                        f.write('='*80 + '\n')
                        f.write('AUCUNE ISSUE DETECTEE\n')
                        f.write('='*80 + '\n\n')
                        f.write('Excellent! Le code est bien structure.\n')

                console.print(f"[green][OK] Rapport texte genere : {safe_relative_path(output_path)}[/green]", markup=False)
            except Exception as e:
                console.print(f"[red][ERREUR] Erreur lors de la generation du rapport : {e}[/red]", markup=False)
            
    elif args.command == 'push-to-mcp':
        console.print("[yellow]📤 Envoi du rapport à MCP (Fonctionnalité en développement)...[/yellow]")
        console.print(f"Fichier de rapport : {args.report_file}")
        console.print(f"URL MCP : {args.mcp_url}")
        console.print(f"Clé de chiffrement : {'********' if args.encryption_key else 'Non fournie'}")
        console.print(f"Tag : {args.tag or 'Non spécifié'}")
        console.print(f"Priorité : {args.priority}")
        # Placeholder for actual MCP integration logic

    elif args.command == 'codeql-scan':
        console.print("[yellow]Lancement de l\'analyse CodeQL...[/yellow]", markup=False)

        # Import CodeQLPlugin here to avoid circular dependencies and only if needed
        from .plugins.codeql_plugin import CodeQLPlugin

        try:
            # Assume args.path[0] is the main source root for now
            codeql_plugin = CodeQLPlugin(license_token=os.getenv("GITHUB_TOKEN", args.github_token)) # Use os.getenv

            # Prepare kwargs for analyze()
            analyze_kwargs = {
                'ruleset': args.query_suite,
                'sarif_output_path': args.sarif_output
            }
            # Add language if specified
            if args.lang:
                analyze_kwargs['language'] = args.lang

            analysis_results = codeql_plugin.analyze(
                path=args.path[0],
                **analyze_kwargs
            )
            console.print("[blue][OK] Analyse CodeQL terminee.[/blue]", markup=False)
            if analysis_results.issues:
                console.print(f"[bold red]Issues CodeQL trouvees : {len(analysis_results.issues)}[/bold red]", markup=False)
                for issue in analysis_results.issues:
                    console.print(f"- [red]{issue.severity.value}[/red]: {issue.message} ({issue.file}:{issue.line})", markup=False)
            else:
                console.print("[green][OK] Aucune issue CodeQL trouvee.[/green]", markup=False)

        except RuntimeError as e:
            console.print(f"[red][ERREUR] Erreur lors de l\'initialisation ou de l\'analyse CodeQL: {e}[/red]", markup=False)
        except Exception as e:
            console.print(f"[red][ERREUR] Une erreur inattendue est survenue lors de l\'analyse CodeQL: {e}[/red]", markup=False)

    elif args.command == 'verify-codeql':
        console.print("="*80, markup=False)
        console.print("VERIFICATION DE L\'INSTALLATION CODEQL", markup=False)
        console.print("="*80, markup=False)
        console.print("", markup=False)

        import subprocess
        import shutil
        import yaml

        all_checks_passed = True

        # 1. Check Python version
        console.print("[blue]1. Verification de la version Python...[/blue]", markup=False)
        python_version = sys.version_info
        if python_version >= (3, 8):
            console.print(f"   [OK] Python {python_version.major}.{python_version.minor}.{python_version.micro}", markup=False)
        else:
            console.print(f"   [ERREUR] Python {python_version.major}.{python_version.minor}.{python_version.micro} (Python 3.8+ requis)", markup=False)
            all_checks_passed = False

        # 2. Check CodeQL CLI installation
        console.print("\n[blue]2. Verification de CodeQL CLI...[/blue]", markup=False)

        # Try to load config (prefer project-local config.yaml)
        config_path = Path("config.yaml")
        if not config_path.exists():
            config_path = Path(__file__).parent.parent / "config.yaml"

        codeql_path = "codeql"
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                    codeql_path = config.get('codeql', {}).get('cli_path', 'codeql')
                console.print(f"   [INFO] Configuration trouvee: {config_path}", markup=False)
                console.print(f"   [INFO] Chemin CodeQL: {codeql_path}", markup=False)
            except Exception as e:
                console.print(f"   [WARNING] Erreur lors de la lecture de la config: {e}", markup=False)

        try:
            result = subprocess.run([codeql_path, "--version"], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                version_output = result.stdout.strip().split('\n')[0]
                console.print(f"   [OK] CodeQL CLI installe: {version_output}", markup=False)
            else:
                console.print(f"   [ERREUR] CodeQL CLI non accessible", markup=False)
                all_checks_passed = False
        except FileNotFoundError:
            console.print(f"   [ERREUR] CodeQL CLI non trouve a: {codeql_path}", markup=False)
            console.print(f"   [INFO] Installer CodeQL ou mettre a jour codeql_config.yaml", markup=False)
            all_checks_passed = False
        except subprocess.TimeoutExpired:
            console.print(f"   [ERREUR] CodeQL CLI timeout", markup=False)
            all_checks_passed = False
        except Exception as e:
            console.print(f"   [ERREUR] Erreur inattendue: {e}", markup=False)
            all_checks_passed = False

        # 3. Check tree-sitter installation
        console.print("\n[blue]3. Verification de tree-sitter...[/blue]", markup=False)
        try:
            import tree_sitter
            try:
                version = tree_sitter.__version__
                console.print(f"   [OK] tree-sitter installe (version {version})", markup=False)
            except AttributeError:
                console.print(f"   [OK] tree-sitter installe", markup=False)
        except ImportError:
            console.print("   [ERREUR] tree-sitter non installe", markup=False)
            console.print("   [INFO] Installer avec: pip install tree-sitter", markup=False)
            all_checks_passed = False

        try:
            import tree_sitter_python
            console.print(f"   [OK] tree-sitter-python installe", markup=False)
        except ImportError:
            console.print("   [WARNING] tree-sitter-python non installe", markup=False)
            console.print("   [INFO] Installer avec: pip install tree-sitter-python", markup=False)

        # 4. Check required Python packages
        console.print("\n[blue]4. Verification des packages Python requis...[/blue]", markup=False)
        required_packages = {
            'rich': 'rich',
            'pyyaml': 'PyYAML',
            'sarif_om': 'sarif-om',
            'python_dotenv': 'python-dotenv'
        }

        for module_name, package_name in required_packages.items():
            try:
                __import__(module_name.replace('-', '_'))
                console.print(f"   [OK] {package_name} installe", markup=False)
            except ImportError:
                console.print(f"   [WARNING] {package_name} non installe", markup=False)
                console.print(f"   [INFO] Installer avec: pip install {package_name}", markup=False)

        # 5. Summary
        console.print("\n" + "="*80, markup=False)
        if all_checks_passed:
            console.print("[OK] TOUTES LES VERIFICATIONS CRITIQUES SONT PASSEES", markup=False)
            console.print("", markup=False)
            console.print("Vous pouvez maintenant utiliser:", markup=False)
            console.print("  - nvyz codeql-scan <path> --query-suite security-extended", markup=False)
            console.print("  - nvyz semantic-scan <path> --lang python --output report.txt", markup=False)
        else:
            console.print("[ERREUR] CERTAINES VERIFICATIONS ONT ECHOUE", markup=False)
            console.print("", markup=False)
            console.print("Veuillez corriger les erreurs ci-dessus avant d\'utiliser nvyz.", markup=False)
        console.print("="*80, markup=False)

    elif args.command == 'secret-scan':
        console.print("[yellow]Recherche de secrets en cours...[/yellow]", markup=False)
        all_paths = resolve_path_patterns(args.path)
        if not all_paths:
            console.print("[yellow][WARNING] Aucun fichier trouve pour la recherche de secrets.[/yellow]", markup=False)
            return

        scanner_results = scan_secrets(all_paths, args.entropy_threshold, args.exclude)

        console.print("[blue][OK] Recherche de secrets terminee.[/blue]", markup=False)
        if scanner_results.issues:
            console.print(f"[bold red]Secrets potentiels trouves : {len(scanner_results.issues)}[/bold red]", markup=False)
            for issue in scanner_results.issues:
                console.print(f"- [red]{issue.severity.value}[/red]: {issue.message} ({issue.file}:{issue.line})", markup=False)
        else:
            console.print("[green][OK] Aucun secret potentiel trouve.[/green]", markup=False)

        # Write output file if specified
        if args.output:
            try:
                output_path = Path(args.output)
                format_type = args.format if args.format else ('md' if output_path.suffix == '.md' else 'txt')

                with open(output_path, 'w', encoding='utf-8') as f:
                    if format_type == 'md':
                        f.write('# Rapport de Scan de Secrets - nvyz\n\n')
                        f.write(f'**Fichiers analyses:** {len(all_paths)}\n\n')
                        f.write(f'**Secrets potentiels trouves:** {len(scanner_results.issues)}\n\n')

                        if scanner_results.issues:
                            f.write('## Issues Detectees\n\n')
                            for idx, issue in enumerate(scanner_results.issues, 1):
                                f.write(f'### [{idx}] {issue.severity.value}: {issue.rule_id}\n\n')
                                f.write(f'- **Fichier:** `{issue.file}`\n')
                                f.write(f'- **Ligne:** {issue.line}\n')
                                f.write(f'- **Message:** {issue.message}\n\n')
                        else:
                            f.write('## Resultat\n\n')
                            f.write('✅ Aucun secret potentiel trouve.\n')
                    else:
                        f.write('='*80 + '\n')
                        f.write('RAPPORT DE SCAN DE SECRETS - nvyz\n')
                        f.write('='*80 + '\n\n')
                        f.write(f'Fichiers analyses: {len(all_paths)}\n')
                        f.write(f'Secrets potentiels trouves: {len(scanner_results.issues)}\n\n')

                        if scanner_results.issues:
                            for idx, issue in enumerate(scanner_results.issues, 1):
                                f.write(f'[{idx}] {issue.severity.value}: {issue.rule_id}\n')
                                f.write(f'    Fichier: {issue.file}\n')
                                f.write(f'    Ligne: {issue.line}\n')
                                f.write(f'    Message: {issue.message}\n\n')
                        else:
                            f.write('[OK] Aucun secret potentiel trouve.\n')

                console.print(f"[green][OK] Rapport genere: {safe_relative_path(output_path)}[/green]", markup=False)
            except Exception as e:
                console.print(f"[red][ERREUR] Impossible d\'ecrire le rapport: {e}[/red]", markup=False)

    elif args.command == 'security-taint':
        console.print("[yellow]Lancement de l\'analyse de taint...[/yellow]", markup=False)
        all_paths = resolve_path_patterns(args.path)
        if not all_paths:
            console.print("[yellow][WARNING] Aucun fichier trouve pour l\'analyse de taint.[/yellow]", markup=False)
            return
        
        if not args.sensitive_patterns or not args.entry_points or not args.sinks:
            console.print("[red]Les arguments --sensitive-patterns, --entry-points et --sinks sont obligatoires[/red]")
            return

        taint_results = analyze_taint(all_paths, args.sensitive_patterns, args.entry_points, args.sinks, console)

        console.print("[blue][OK] Analyse de taint terminee.[/blue]", markup=False)
        if taint_results.issues:
            console.print(f"[bold red]Issues de taint trouvees : {len(taint_results.issues)}[/bold red]", markup=False)
            for issue in taint_results.issues:
                console.print(f"- [red]{issue.severity.value}[/red]: {issue.message} ({issue.file}:{issue.line})", markup=False)
        else:
            console.print("[green][OK] Aucune issue de taint trouvee.[/green]", markup=False)

        # Write output file if specified
        if args.output:
            try:
                output_path = Path(args.output)
                format_type = args.format if args.format else ('md' if output_path.suffix == '.md' else 'txt')

                with open(output_path, 'w', encoding='utf-8') as f:
                    if format_type == 'md':
                        f.write('# Rapport d\'Analyse de Taint (Flux de Données) - nvyz\n\n')
                        f.write(f'**Fichiers analysés:** {len(all_paths)}\n\n')
                        f.write(f'**Issues de taint détectées:** {len(taint_results.issues)}\n\n')
                        f.write(f'**Patterns sensibles:** {", ".join(args.sensitive_patterns)}\n\n')
                        f.write(f'**Entry points:** {", ".join(args.entry_points)}\n\n')
                        f.write(f'**Sinks:** {", ".join(args.sinks)}\n\n')

                        if taint_results.issues:
                            f.write('## Issues Détectées\n\n')
                            for idx, issue in enumerate(taint_results.issues, 1):
                                f.write(f'### [{idx}] {issue.severity.value}: {issue.rule_id}\n\n')
                                f.write(f'- **Fichier:** `{issue.file}`\n')
                                f.write(f'- **Ligne:** {issue.line}\n')
                                f.write(f'- **Message:** {issue.message}\n\n')
                        else:
                            f.write('## Résultat\n\n')
                            f.write('✅ Aucune issue de taint détectée.\n\n')
                            f.write('Aucun flux de données sensibles détecté entre les sources (entry points) et les sinks dangereux.\n')
                    else:
                        f.write('='*80 + '\n')
                        f.write('RAPPORT D\'ANALYSE DE TAINT (FLUX DE DONNEES) - nvyz\n')
                        f.write('='*80 + '\n\n')
                        f.write(f'Fichiers analyses: {len(all_paths)}\n')
                        f.write(f'Issues de taint detectees: {len(taint_results.issues)}\n\n')
                        f.write(f'Patterns sensibles: {", ".join(args.sensitive_patterns)}\n')
                        f.write(f'Entry points: {", ".join(args.entry_points)}\n')
                        f.write(f'Sinks: {", ".join(args.sinks)}\n\n')

                        if taint_results.issues:
                            for idx, issue in enumerate(taint_results.issues, 1):
                                f.write(f'[{idx}] {issue.severity.value}: {issue.rule_id}\n')
                                f.write(f'    Fichier: {issue.file}\n')
                                f.write(f'    Ligne: {issue.line}\n')
                                f.write(f'    Message: {issue.message}\n\n')
                        else:
                            f.write('[OK] Aucune issue de taint detectee.\n\n')
                            f.write('Aucun flux de donnees sensibles detecte entre les sources et les sinks.\n')

                console.print(f"[green][OK] Rapport genere: {safe_relative_path(output_path)}[/green]", markup=False)
            except Exception as e:
                console.print(f"[red][ERREUR] Impossible d\'ecrire le rapport: {e}[/red]", markup=False)

    elif args.command == 'sonar-scan':
        console.print("[yellow]🔍 Lancement du scan SonarQube local...[/yellow]")
        from .plugins.sonarqube_plugin import SonarQubePlugin
        
        try:
            sonar_plugin = SonarQubePlugin(mode="offline")
            sonar_results = sonar_plugin.analyze(
                path=args.path[0], # Assume single path for now
                rules=args.rules,
                sonar_project_file=args.sonar_project_file
            )
            # Display results
            if sonar_results.issues:
                console.print(f"[bold red]Issues SonarQube trouvées : {len(sonar_results.issues)}[/bold red]")
                for issue in sonar_results.issues:
                    console.print(f"- [red]{issue.severity.value}[/red]: {issue.message} ({issue.file}:{issue.line})")
            else:
                console.print("[green]🎉 Aucune issue SonarQube trouvée.[/green]")

            if args.output:
                sarif_log = generate_sarif_report(sonar_results, tool_name="SonarQube (nvyz plugin)")
                output_path = Path(args.output)
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(sarif_log.dict(by_alias=True, exclude_unset=True), f, indent=2, ensure_ascii=False)
                console.print(f"[green]✅ Rapport SARIF SonarQube généré : {safe_relative_path(output_path)}[/green]")

        except RuntimeError as e:
            console.print(f"[red]❌ Erreur lors de l\'initialisation ou de l\'analyse SonarQube: {e}[/red]")
        except Exception as e:
            console.print(f"[red]❌ Une erreur inattendue est survenue lors de l\'analyse SonarQube: {e}[/red]")

    elif args.command == 'sonar-import':
        console.print("[yellow]📥 Importation des issues SonarQube depuis le serveur...[/yellow]")
        from .plugins.sonarqube_plugin import SonarQubePlugin
        
        try:
            # Token from env var or arg
            token = os.getenv("SONAR_TOKEN", args.token)
            if not token:
                console.print("[red]❌ Le token SonarQube (--token ou SONAR_TOKEN) est obligatoire pour le mode online.[/red]")
                return

            sonar_plugin = SonarQubePlugin(mode="online", server_url=args.server_url, token=token)
            sonar_results = sonar_plugin.analyze(
                project_key=args.project_key,
                quality_gate=args.quality_gate
            )
            # Display results
            if sonar_results.issues:
                console.print(f"[bold red]Issues SonarQube importées : {len(sonar_results.issues)}[/bold red]")
                for issue in sonar_results.issues:
                    console.print(f"- [red]{issue.severity.value}[/red]: {issue.message} ({issue.file}:{issue.line})")
            else:
                console.print("[green]🎉 Aucune issue SonarQube importée.[/green]")

            if args.output:
                sarif_log = generate_sarif_report(sonar_results, tool_name="SonarQube Import (nvyz plugin)")
                output_path = Path(args.output)
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(sarif_log.dict(by_alias=True, exclude_unset=True), f, indent=2, ensure_ascii=False)
                console.print(f"[green]✅ Rapport SARIF SonarQube généré : {safe_relative_path(output_path)}[/green]")

        except RuntimeError as e:
            console.print(f"[red]❌ Erreur lors de l\'initialisation ou de l\'importation SonarQube: {e}[/red]")
        except Exception as e:
            console.print(f"[red]❌ Une erreur inattendue est survenue lors de l\'importation SonarQube: {e}[/red]")

    elif args.command == 'sonar-metrics':
        console.print("[yellow]📊 Calcul des métriques SonarQube... (Fonctionnalité en développement)[/yellow]")
        console.print(f"Chemins : {args.path}")
        console.print(f"Profil de qualité : {args.quality_profile}")
        # Placeholder for actual SonarQube metrics logic
        console.print("[red]❌ La commande sonar-metrics n\'est pas encore implémentée. (Utilise SonarQubePlugin en mode 'metrics')[/red]")

    elif args.command == 'fuse-results':
        console.print("[blue]🧪 Fusion des rapports SARIF...[/blue]")
        
        # Placeholder for actual SARIF loading and merging logic
        # For now, just confirm inputs and output
        console.print(f"Fichiers d\'entrée : {args.input_files}")
        console.print(f"Fichier de sortie : {args.output}")
        console.print(f"Stratégie de fusion : {args.strategy}")
        console.print(f"Déduplication : {args.deduplicate}")

        # Dummy merged result
        dummy_analysis_result = AnalysisResult(issues=[
            Issue(file="merged.py", message="Dummy merged issue", severity=Severity.INFO, rule_id="MERGED001", tool="nvyz-merger")
        ])

        try:
            sarif_log = generate_sarif_report(dummy_analysis_result, tool_name="nvyz SARIF Merger")
            output_path = Path(args.output)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(sarif_log.dict(by_alias=True, exclude_unset=True), f, indent=2, ensure_ascii=False)
            console.print(f"[green]✅ Rapport SARIF unifié généré : {safe_relative_path(output_path)}[/green]")
        except Exception as e:
            console.print(f"[red]❌ Erreur lors de la génération du rapport SARIF fusionné : {e}[/red]")

    elif args.command == 'plugin':
        current_config = load_config()

        if args.plugin_command == 'list':
            console.print("[blue]Plugins disponibles :[/blue]")
            # Hardcoded list for now, will be dynamic later
            available_plugins = {
                "codeql": "Intégration GitHub CodeQL",
                "sonarqube": "Intégration SonarQube"
            }
            for name, desc in available_plugins.items():
                status_icon = "[green]✅ Actif[/green]" if current_config.plugins.get(name, PluginConfig()).enabled else "[red]❌ Inactif[/red]"
                console.print(f"- [bold]{name}[/bold]: {desc} {status_icon}")
            
        elif args.plugin_command == 'enable':
            plugin_name = args.plugin_name
            console.print(f"[blue]Activation du plugin '{plugin_name}'...[/blue]")

            if plugin_name not in current_config.plugins:
                current_config.plugins[plugin_name] = PluginConfig() # Create if not exists

            current_config.plugins[plugin_name].enabled = True
            if args.token_env:
                current_config.plugins[plugin_name].token_env = args.token_env
            if args.set:
                for setting in args.set:
                    key, value = setting.split('=', 1)
                    current_config.plugins[plugin_name].settings[key] = value

            save_config(current_config)
            console.print(f"[green]Plugin '{plugin_name}' activé et configuré.[/green]")
        else:
            parser_plugin.print_help()
    else:
        parser.print_help()