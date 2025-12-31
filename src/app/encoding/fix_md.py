#!/usr/bin/env python3
# fix_md.py
"""
Corrige les fichiers Markdown :
  - Encodage → UTF-8
  - Décode les entités HTML (&nbsp; → espace, etc.)
  - Encode les espaces dans les liens/images ([text](path/file name.md) → [text](path/file%20name.md))
  - Nettoie les id HTML (id="xxx " → id="xxx")
  - Remplit les fichiers vides

Usage :
  python fix_md.py -P "docs/**/*.md" --dry-run
  python fix_md.py -P "si/*.md" --backup
"""

import argparse
import sys
import re
import urllib.parse
import html
from pathlib import Path
from typing import List, Tuple

from ..core.pathglob import resolve_path_patterns

import chardet


# === RÈGLES DE CORRECTION ===

def decode_html_entities(text: str) -> str:
    """Décode les entités HTML courantes (&nbsp; → ' ', etc.)"""
    # D'abord les numériques (&#160; → \xa0), puis nommées (&nbsp; → \xa0), puis html.unescape
    text = re.sub(r"&#(\d+);", lambda m: chr(int(m.group(1))), text)
    text = re.sub(r"&#x([0-9a-fA-F]+);", lambda m: chr(int(m.group(1), 16)), text)
    text = html.unescape(text)
    return text


def fix_anchor_ids(text: str) -> str:
    """Supprime les espaces en fin de `id=\"...\"` dans les balises HTML"""
    return re.sub(r'(id\s*=\s*"[^"]*?)"\s+([^>]*>)', r'\1\2', text)


def encode_spaces_in_links(text: str) -> str:
    """Encode les espaces dans les URLs de liens/images Markdown :
    [text](path/file name.md) → [text](path/file%20name.md)
    ![alt](uploads/xxx xxx.png) → ![alt](uploads/xxx%20xxx.png)
    """
    def repl_link(match):
        pre, url, post = match.groups()
        # Ne pas encoder les % déjà présents (éviter double encodage)
        if "%" not in url:
            url = urllib.parse.quote(url, safe="/:?#[]@!$&'()*+,;=-._~")
        return f"{pre}{url}{post}"

    # Markdown links & images
    text = re.sub(r"(!?[\[.*?\]\()([^)\s]+?)([\])])", repl_link, text)
    # HTML <a href="">, <img src="">
    text = re.sub(r'(<(?:a|img)\s[^>]*?(?:href|src)\s*=\s*["\'])([^"\'\s>]+?)(["\'][^>]*?>)', repl_link, text, flags=re.IGNORECASE)
    return text


def ensure_non_empty(content: str) -> str:
    """Si vide (ou uniquement du blanc), ajoute un commentaire"""
    stripped = content.strip()
    if not stripped:
        return "<!-- À compléter -->\n"
    return content

def fix_file_encoding_and_content(path: Path, dry_run: bool = False, backup: bool = False) -> Tuple[bool, str]:
    """
    Corrige un fichier .md :
      1. Détecte et re-encode en UTF-8
      2. Applique les corrections de contenu
    Retourne (ok: bool, message: str)
    """
    try:
        # 🔍 Détection initiale
        raw = path.read_bytes()
        detected = chardet.detect(raw)
        encoding = detected["encoding"] or "utf-8"
        confidence = detected["confidence"] or 0.0

        try:
            text = raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            # fallback hard
            text = raw.decode("utf-8", errors="replace")
            encoding = "utf-8 (fallback)"
            confidence = 0.0

        # 🛠️ CORRECTIONS
        original = text
        text = decode_html_entities(text)
        text = fix_anchor_ids(text)
        text = encode_spaces_in_links(text)
        text = ensure_non_empty(text)

        changed = (text != original) or (encoding.lower() not in ("utf-8", "utf8"))

        if not changed:
            return True, "ok (déjà conforme)"

        # 💾 ÉCRITURE
        if not dry_run:
            if backup and path.exists():
                bak = path.with_suffix(path.suffix + ".bak")
                path.replace(bak)  # backup atomique

            # Toujours écrire en UTF-8 *sans BOM* (standard GitHub/GitLab)
            path.write_text(text, encoding="utf-8", newline="\n")

        status = "✅ corrigé" if not dry_run else "🔧 (dry-run)"
        details = []
        if encoding.lower() not in ("utf-8", "utf8"):
            details.append(f"encoding:{encoding}({confidence:.0%})→UTF-8")
        if text != original:
            details.append("contenu modifié")
        return True, f"{status} [{', '.join(details)}]"

    except Exception as e:
        return False, f"❌ échec: {e}"


# === CLI ===

def main_cli() -> int:
    parser = argparse.ArgumentParser(
        description="Corrige les fichiers Markdown (encodage, liens, entités HTML, anchors)."
    )
    parser.add_argument(
        "--path-pattern", "-P",
        nargs="+",
        required=True,
        metavar="PATTERN",
        help="Motif(s) de fichiers Markdown (ex: 'si/**/*.md')"
    )
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Simuler sans modifier les fichiers"
    )
    parser.add_argument(
        "--backup",
        action="store_true",
        help="Créer un .bak avant modification"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="N'afficher que les erreurs"
    )

    args = parser.parse_args()

    try:
        all_paths = resolve_path_patterns(args.path_pattern, recursive=True)
    except Exception as e:
        print(f"❌ Échec résolution des motifs : {e}", file=sys.stderr)
        return 1

    md_paths = [
        p for p in all_paths
        if p.is_file() and p.suffix.lower() == ".md"
    ]

    if not md_paths:
        print("⚠️ Aucun fichier Markdown trouvé.", file=sys.stderr)
        return 1

    errors = 0
    for p in md_paths:
        ok, msg = fix_file_encoding_and_content(p, dry_run=args.dry_run, backup=args.backup)
        if not ok:
            errors += 1
        if not args.quiet or not ok:
            icon = "  " if ok and args.quiet else ("✅" if ok else "❌")
            print(f"{icon} {p.relative_to(Path.cwd())} → {msg}")

    if errors:
        print(f"\n❌ {errors} erreur(s)", file=sys.stderr)
        return 1
    else:
        print(f"\n✅ {len(md_paths)} fichier(s) traité(s)", file=sys.stderr)
        return 0


# === API réutilisable ===

def fix_markdown_files(patterns: List[str], dry_run: bool = False, backup: bool = False) -> List[dict]:
    """API programmatique : retourne un rapport détaillé"""
    try:
        paths = resolve_path_patterns(patterns)
        md_files = [p for p in paths if p.suffix.lower() == ".md"]
    except Exception as e:
        return [{"error": f"resolve_path_patterns failed: {e}"}]

    results = []
    for p in md_files:
        ok, msg = fix_file_encoding_and_content(p, dry_run=dry_run, backup=backup)
        results.append({
            "path": str(p),
            "success": ok,
            "message": msg,
            "dry_run": dry_run
        })
    return results


if __name__ == "__main__":
    sys.exit(main_cli())
