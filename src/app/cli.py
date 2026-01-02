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
    parser_semantic_scan.add_argument('--output', help='Chemin du fichier de sortie SARIF.') # New argument

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
    parser_codeql_scan.add_argument('--query-suite', default='security', help='Suite de requêtes CodeQL à utiliser (ex: security, security-extended).')
    parser_codeql_scan.add_argument('--github-token', help='Token GitHub pour l\'accès à GitHub Advanced Security (variable d\'environnement).')
    parser_codeql_scan.add_argument('--sarif-output', help='Chemin du fichier de sortie SARIF pour les résultats CodeQL.')

    # Commande secret-scan
    parser_secret_scan = subparsers.add_parser('secret-scan', help='Détecte les secrets codés en dur dans le code.')
    parser_secret_scan.add_argument('path', nargs='+', help='Chemins ou motifs (globs) à analyser.')
    parser_secret_scan.add_argument('--entropy-threshold', type=float, default=4.5, help='Seuil d\'entropie pour la détection de secrets.')
    parser_secret_scan.add_argument('--exclude', nargs='+', help='Motifs (globs) de fichiers/répertoires à exclure.')

    # Commande security-taint
    parser_security_taint = subparsers.add_parser('security-taint', help='Effectue une analyse de flux de données sensibles (taint analysis).')
    parser_security_taint.add_argument('path', nargs='+', help='Chemins ou motifs (globs) à analyser.')
    parser_security_taint.add_argument('--sensitive-patterns', nargs='+', help='Patterns de données sensibles à rechercher (ex: GDPR, PCI).')
    parser_security_taint.add_argument('--entry-points', nargs='+', help='Fichiers/fonctions considérés comme points d\'entrée des données.')
    parser_security_taint.add_argument('--sinks', nargs='+', help='Fichiers/fonctions considérés comme des sinks (où les données sensibles ne devraient pas arriver).')

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

            if not args.quiet:
                status_color = "green"
                status_icon = "✅"
                if error:
                    status_color = "red"
                    status_icon = "❌"
                elif is_issue:
                    status_color = "yellow"
                    status_icon = "⚠️ "

                console.print(f"[{status_color}]{status_icon}[/{status_color}] {path}")
                if error:
                    console.print(f"    [red]→ Erreur: {error}[/red]")
                else:
                    console.print(f"    → Encodage: {encoding} (confiance: {confidence:.2%})")
            elif is_issue:
                console.print(f"[yellow]⚠️  {path}: {encoding} ({confidence:.0%})[/yellow]")


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
            icon = "✅" if success else "❌"
            console.print(f"{icon} {path} → {message}", markup=False)
            
    elif args.command == 'semantic-scan':
        console.print("[blue]🚀 Démarrage de l\'analyse sémantique...[/blue]")

        all_paths = resolve_path_patterns(args.path)
        if not all_paths:
            console.print("[yellow]⚠️ Aucun fichier trouvé pour l\'analyse.[/yellow]")
            return

        # Placeholder for auto-detection logic based on file extension
        language = args.lang
        if not language:
            if args.auto_detect_lang:
                sys.stderr.write("❌ L'auto-détection du langage n'est pas encore implémentée. Veuillez spécifier --lang.\n")
                return
            else:
                sys.stderr.write("Veuillez spécifier le langage avec --lang\n")
                return
        
        parser = get_parser(language)
        if not parser:
            console.print(f"[red]❌ Impossible de charger le parseur pour le langage '{language}'.[/red]. Veuillez vérifier l\'installation de tree-sitter et la compilation des grammaires.")
            return
        
        analysis_results = AnalysisResult()
        
        for p in all_paths:
            if p.is_file():
                try:
                    source_code = p.read_bytes()
                    tree = parser.parse(source_code)
                    
                    # Placeholder for actual semantic rules/issue detection
                    # For now, we'll just report a dummy issue
                    console.print(f"[green]✅ Analysé : {safe_relative_path(p)}[/green]")
                    
                    # Example dummy issue
                    dummy_issue = Issue(
                        file=str(safe_relative_path(p)),
                        line=1,
                        message="Exemple d\'issue sémantique (à implémenter)",
                        severity=Severity.INFO,
                        rule_id="N001",
                        tool="nvyz-semantic"
                    )
                    analysis_results.issues.append(dummy_issue)

                except Exception as e:
                    console.print(f"[red]❌ Erreur lors de l\'analyse de {safe_relative_path(p)}: {e}[/red]")
            else:
                console.print(f"[yellow]⚠️ Ignoré (n\'est pas un fichier) : {safe_relative_path(p)}[/yellow]")

        console.print("[blue]✨ Analyse sémantique terminée.[/blue]")
        if analysis_results.issues:
            console.print(f"[bold red]Issues trouvées : {len(analysis_results.issues)}[/bold red]")
            for issue in analysis_results.issues:
                console.print(f"- [red]{issue.severity.value}[/red]: {issue.message} ({issue.file}:{issue.line})")
        else:
            console.print("[green]🎉 Aucune issue sémantique trouvée.[/green]")

        if args.output:
            try:
                sarif_log = generate_sarif_report(analysis_results)
                output_path = Path(args.output)
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(sarif_log.dict(by_alias=True, exclude_unset=True), f, indent=2, ensure_ascii=False)
                console.print(f"[green]✅ Rapport SARIF généré : {safe_relative_path(output_path)}[/green]")
            except Exception as e:
                console.print(f"[red]❌ Erreur lors de la génération du rapport SARIF : {e}[/red]")
            
    elif args.command == 'push-to-mcp':
        console.print("[yellow]📤 Envoi du rapport à MCP (Fonctionnalité en développement)...[/yellow]")
        console.print(f"Fichier de rapport : {args.report_file}")
        console.print(f"URL MCP : {args.mcp_url}")
        console.print(f"Clé de chiffrement : {'********' if args.encryption_key else 'Non fournie'}")
        console.print(f"Tag : {args.tag or 'Non spécifié'}")
        console.print(f"Priorité : {args.priority}")
        # Placeholder for actual MCP integration logic

    elif args.command == 'codeql-scan':
        console.print("[yellow]🚀 Lancement de l\'analyse CodeQL...[/yellow]")
        
        # Import CodeQLPlugin here to avoid circular dependencies and only if needed
        from .plugins.codeql_plugin import CodeQLPlugin

        try:
            # Assume args.path[0] is the main source root for now
            codeql_plugin = CodeQLPlugin(license_token=os.getenv("GITHUB_TOKEN", args.github_token)) # Use os.getenv
            analysis_results = codeql_plugin.analyze(
                path=args.path[0],
                ruleset=args.query_suite,
                sarif_output_path=args.sarif_output
            )
            console.print("[blue]✨ Analyse CodeQL terminée.[/blue]")
            if analysis_results.issues:
                console.print(f"[bold red]Issues CodeQL trouvées : {len(analysis_results.issues)}[/bold red]")
                for issue in analysis_results.issues:
                    console.print(f"- [red]{issue.severity.value}[/red]: {issue.message} ({issue.file}:{issue.line})")
            else:
                console.print("[green]🎉 Aucune issue CodeQL trouvée.[/green]")

        except RuntimeError as e:
            console.print(f"[red]❌ Erreur lors de l\'initialisation ou de l\'analyse CodeQL: {e}[/red]")
        except Exception as e:
            console.print(f"[red]❌ Une erreur inattendue est survenue lors de l\'analyse CodeQL: {e}[/red]")

    elif args.command == 'secret-scan':
        console.print("[yellow]🕵️‍♂️ Recherche de secrets en cours...[/yellow]")
        all_paths = resolve_path_patterns(args.path)
        if not all_paths:
            console.print("[yellow]⚠️ Aucun fichier trouvé pour la recherche de secrets.[/yellow]")
            return
        
        scanner_results = scan_secrets(all_paths, args.entropy_threshold, args.exclude)
        
        console.print("[blue]✨ Recherche de secrets terminée.[/blue]")
        if scanner_results.issues:
            console.print(f"[bold red]Secrets potentiels trouvés : {len(scanner_results.issues)}[/bold red]")
            for issue in scanner_results.issues:
                console.print(f"- [red]{issue.severity.value}[/red]: {issue.message} ({issue.file}:{issue.line})")
        else:
            console.print("[green]🎉 Aucun secret potentiel trouvé.[/green]")

    elif args.command == 'security-taint':
        console.print("[yellow]🚨 Lancement de l\'analyse de taint...[/yellow]")
        all_paths = resolve_path_patterns(args.path)
        if not all_paths:
            console.print("[yellow]⚠️ Aucun fichier trouvé pour l\'analyse de taint.[/yellow]")
            return
        
        if not args.sensitive_patterns or not args.entry_points or not args.sinks:
            console.print("[red]Les arguments --sensitive-patterns, --entry-points et --sinks sont obligatoires[/red]")
            return

        taint_results = analyze_taint(all_paths, args.sensitive_patterns, args.entry_points, args.sinks)

        console.print("[blue]✨ Analyse de taint terminée.[/blue]")
        if taint_results.issues:
            console.print(f"[bold red]Issues de taint trouvées : {len(taint_results.issues)}[/bold red]")
            for issue in taint_results.issues:
                console.print(f"- [red]{issue.severity.value}[/red]: {issue.message} ({issue.file}:{issue.line})")
        else:
            console.print("[green]🎉 Aucune issue de taint trouvée.[/green]")

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