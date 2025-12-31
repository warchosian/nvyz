#!/usr/bin/env python3
# G:\home\firmin\.local\bin\check_md.py
"""
Vérifie l'encodage de fichiers Markdown via des chemins ou motifs (globs).

Supporte :
  - Chemins exacts : 'README.md'
  - Wildcards : '*.md', 'docs/[A-Z]*.md'
  - Récursion : 'content/**/*.md'

Dépendances : chardet (à installer via pip/conda)
"""

import argparse
import sys
from pathlib import Path
from typing import List

from ..core.pathglob import resolve_path_patterns

import chardet


def check_md(file_path: Path) -> dict:
    """Vérifie l'encodage d'un fichier Markdown.

    Args:
        file_path (Path): Chemin vers le fichier (doit exister).

    Returns:
        dict: Résultat avec 'path', 'encoding', 'confidence', 'raw_data', 'error'.
    """
    result = {
        "path": file_path,
        "encoding": None,
        "confidence": 0.0,
        "raw_data": None,
        "error": None
    }

    try:
        if not file_path.is_file():
            result["error"] = "Not a file or does not exist"
            return result

        raw_data = file_path.read_bytes()
        result["raw_data"] = raw_data

        detected = chardet.detect(raw_data)
        result["encoding"] = detected["encoding"]
        result["confidence"] = detected["confidence"]

    except Exception as e:
        result["error"] = str(e)

    return result


def main_cli() -> int:
    """CLI entry point — retourne le code de sortie (0 = OK, 1 = erreur)."""
    parser = argparse.ArgumentParser(
        description="Vérifie l'encodage de fichiers Markdown (supporte les globs)."
    )
    parser.add_argument(
        "--path-pattern", "-P",
        nargs="+",
        required=True,
        metavar="PATTERN",
        help="Motif(s) de chemin(s) Markdown (ex: '*.md', 'docs/**/*.md'). "
             "Les motifs sans extension .md sont acceptés, mais seuls les .md seront traités."
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.7,
        help="Seuil minimal de confiance pour considérer l'encodage comme fiable (défaut: 0.7)"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Mode silencieux : n'affiche que les erreurs ou encodages non UTF-8"
    )

    args = parser.parse_args()

    # 🔍 Résolution des motifs → chemins concrets
    try:
        all_paths = resolve_path_patterns(args.path_pattern, recursive=True)
    except (ValueError, OSError) as e:
        print(f"❌ Échec de la résolution des motifs : {e}", file=sys.stderr)
        return 1

    # 🔎 Filtrer *seulement* les fichiers .md (insensible à la casse sous Windows)
    md_paths = [
        p for p in all_paths
        if p.is_file() and p.suffix.lower() == ".md"
    ]

    if not md_paths:
        print("⚠️  Aucun fichier Markdown (.md) trouvé.", file=sys.stderr)
        return 1

    has_issue = False
    for p in md_paths:
        res = check_md(p)
        encoding = res["encoding"] or "inconnu"
        confidence = res["confidence"]
        error = res["error"]

        # ✅ Comportement par défaut : tout afficher
        if not args.quiet:
            status = "❌" if error else ("⚠️ " if confidence < args.min_confidence else "✅")
            print(f"{status} {p}")
            if error:
                print(f"    → Erreur: {error}")
            else:
                print(f"    → Encodage: {encoding} (confiance: {confidence:.2%})")

        # 🔔 Mode silencieux : signaler les problèmes
        if error or (encoding and encoding.upper() not in ("UTF-8", "UTF8")) or confidence < args.min_confidence:
            has_issue = True
            if args.quiet:
                print(f"⚠️  {p}: {encoding} ({confidence:.0%})", file=sys.stderr)

    return 1 if has_issue else 0


# 🧩 API programmatique (réutilisable depuis d'autres modules)
def check_markdown_files(patterns: List[str]) -> List[dict]:
    """API publique : analyse les .md correspondant aux motifs.

    Args:
        patterns: Liste de motifs (ex: ["docs/**/*.md"])

    Returns:
        Liste de résultats (dict), un par fichier Markdown trouvé.
    """
    paths = resolve_path_patterns(patterns)
    md_files = [p for p in paths if p.suffix.lower() == ".md"]
    return [check_md(p) for p in md_files]


# ▶️ Point d'entrée
if __name__ == "__main__":
    sys.exit(main_cli())