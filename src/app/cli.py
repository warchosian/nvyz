"Module CLI pour nvyz."

import argparse
from .encoding.check_md import check_markdown_files
from .encoding.fix_md import fix_markdown_files

def main():
    """Fonction principale appelée par la commande `nvyz`."""
    parser = argparse.ArgumentParser(description='nvyz CLI')
    subparsers = parser.add_subparsers(dest='command', help='Sous-commandes disponibles')

    # Commande check-md
    parser_check_md = subparsers.add_parser('check-md', help='Vérifie l\'encodage des fichiers Markdown')
    parser_check_md.add_argument('files', nargs='+', help='Fichiers ou motifs (globs) à vérifier')

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

        for res in results:
            encoding = res.get("encoding", "inconnu")
            confidence = res.get("confidence", 0.0)
            error = res.get("error")
            path = res.get("path", "Chemin inconnu")

            status = "✅"
            if error:
                status = "❌"
            elif confidence < 0.7:
                status = "⚠️ "
            elif encoding.upper() not in ("UTF-8", "UTF8"):
                status = "⚠️ "

            print(f"{status} {path}")
            if error:
                print(f"    → Erreur: {error}")
            else:
                print(f"    → Encodage: {encoding} (confiance: {confidence:.2%})")

    elif args.command == 'fix-md':
        results = fix_markdown_files(args.files, dry_run=args.dry_run, backup=args.backup)
        if not results:
            print("⚠️  Aucun fichier Markdown (.md) trouvé.")
            return
        
        for res in results:
            path = res.get("path", "Chemin inconnu")
            success = res.get("success", False)
            message = res.get("message", "Aucun message.")
            icon = "✅" if success else "❌"
            print(f"{icon} {path} → {message}")
            
    else:
        parser.print_help()
