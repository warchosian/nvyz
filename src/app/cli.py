"Module CLI pour nvyz."

import argparse
from pathlib import Path
from .encoding.check_md import check_markdown_files
from .encoding.fix_md import fix_markdown_files

def main():
    """Fonction principale appelée par la commande `nvyz`."""
    parser = argparse.ArgumentParser(description='nvyz CLI')
    subparsers = parser.add_subparsers(dest='command', help='Sous-commandes disponibles')

    # Commande check-md
    parser_check_md = subparsers.add_parser('check-md', help='Vérifie l\'encodage des fichiers Markdown')
    parser_check_md.add_argument('files', nargs='+', help='Fichiers ou motifs (globs) à vérifier')
    parser_check_md.add_argument('--quiet', '-q', action='store_true', help='Mode silencieux : n\'affiche que les problèmes')

    # Commande fix-md
    parser_fix_md = subparsers.add_parser('fix-md', help='Corrige l\'encodage et le contenu des fichiers Markdown')
    parser_fix_md.add_argument('files', nargs='+', help='Fichiers ou motifs (globs) à corriger')
    parser_fix_md.add_argument('--dry-run', '-n', action='store_true', help='Simuler sans modifier les fichiers')
    parser_fix_md.add_argument('--backup', action='store_true', help='Créer un .bak avant modification')

    args = parser.parse_args()

    if args.command == 'check-md':
        results = check_markdown_files(args.files)
        if not results:
            print("⚠️  Aucun fichier Markdown (.md) trouvé.")
            return

        min_confidence = 0.7
        for res in results:
            encoding = res.get("encoding", "inconnu")
            confidence = res.get("confidence", 0.0)
            error = res.get("error")
            path_obj = Path(res.get("path", "Chemin inconnu"))
            try:
                path = str(path_obj.relative_to(Path.cwd()))
            except ValueError:
                path = str(path_obj) # Fallback to absolute if not relative

            is_issue = error or (encoding and encoding.upper() not in ("UTF-8", "UTF8", "ASCII")) or confidence < min_confidence

            if not args.quiet:
                status = "✅"
                if error:
                    status = "❌"
                elif is_issue:
                    status = "⚠️ "

                print(f"{status} {path}")
                if error:
                    print(f"    → Erreur: {error}")
                else:
                    print(f"    → Encodage: {encoding} (confiance: {confidence:.2%})")
            elif is_issue:
                print(f"⚠️  {path}: {encoding} ({confidence:.0%})")


    elif args.command == 'fix-md':
        results = fix_markdown_files(args.files, dry_run=args.dry_run, backup=args.backup)
        if not results:
            print("⚠️  Aucun fichier Markdown (.md) trouvé.")
            return
        
        for res in results:
            path_obj = Path(res.get("path", "Chemin inconnu"))
            try:
                path = str(path_obj.relative_to(Path.cwd()))
            except ValueError:
                path = str(path_obj) # Fallback to absolute if not relative

            success = res.get("success", False)
            message = res.get("message", "Aucun message.")
            icon = "✅" if success else "❌"
            print(f"{icon} {path} → {message}")
            
    else:
        parser.print_help()
