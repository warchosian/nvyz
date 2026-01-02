# Documentation des commandes CLI de Phase 1

Ce document détaille les commandes CLI développées durant la Phase 1 du projet "nvyz Code Forge", ainsi que leurs arguments respectifs.

---

## 1. `nvyz semantic-scan`

### Description
Effectue une analyse sémantique du code source pour détecter des problèmes ou extraire des informations structurelles.

### Syntaxe
`nvyz semantic-scan <path> [--lang <lang>] [--auto-detect-lang] [--threshold <level>] [--parallel <num>] [--rules <file1> [<file2> ...]] [--exclude <pattern1> [<pattern2> ...]] [--output <file_path>]`

### Arguments

#### Arguments positionnels
*   `<path>` (obligatoire, multiple)
    *   Chemins ou motifs (globs) des fichiers/répertoires à analyser.
    *   Exemple : `./src`, `main.py`, `src/**/*.js`

#### Arguments optionnels
*   `--lang <lang>`
    *   Spécifie le langage de programmation à analyser (ex: `python`, `javascript`).
    *   Utilisé si l'auto-détection est désactivée ou pour la forcer.
*   `--auto-detect-lang` (flag)
    *   Détecte automatiquement le langage de programmation en fonction de l'extension du fichier.
*   `--threshold <level>` (défaut: `warning`)
    *   Seuil de sévérité minimum des problèmes à inclure dans les rapports (ex: `info`, `warning`, `medium`, `high`, `critical`).
*   `--parallel <num>` (défaut: `1`)
    *   Nombre de processus parallèles à utiliser pour l'analyse afin d'accélérer le traitement.
*   `--rules <file1> [<file2> ...]`
    *   Chemin(s) vers un ou plusieurs fichiers de règles personnalisées à appliquer pendant l'analyse.
*   `--exclude <pattern1> [<pattern2> ...]`
    *   Motifs (globs) de fichiers ou répertoires à exclure de l'analyse.
    *   Exemple : `tests/`, `*.min.js`
*   `--output <file_path>`
    *   Chemin du fichier où le rapport d'analyse SARIF doit être enregistré. Si non spécifié, le rapport est affiché sur la console.

### Exemple d'utilisation
```bash
nvyz semantic-scan ./src --lang python --threshold high --output results.sarif
nvyz semantic-scan my_project/**/*.js --auto-detect-lang --parallel 4 --exclude "node_modules/"
```

---

## 2. `nvyz push-to-mcp`

### Description
Envoie un rapport d'analyse SARIF unifié à la plateforme MCP (Master Control Platform) pour centralisation et suivi.

### Syntaxe
`nvyz push-to-mcp <report_file> --mcp-url <url> [--encryption-key <key>] [--tag <tag_name>] [--priority <level>]`

### Arguments

#### Arguments positionnels
*   `<report_file>` (obligatoire)
    *   Chemin vers le fichier de rapport SARIF unifié à envoyer.

#### Arguments optionnels
*   `--mcp-url <url>` (obligatoire)
    *   L'URL de l'API de la plateforme MCP à laquelle envoyer le rapport.
*   `--encryption-key <key>`
    *   Clé de chiffrement à utiliser pour sécuriser le rapport avant son envoi. Idéalement fournie via une variable d'environnement.
*   `--tag <tag_name>`
    *   Tag ou identifiant pour marquer le rapport dans MCP (ex: numéro de version, SHA de commit).
*   `--priority <level>` (défaut: `MEDIUM`)
    *   Niveau de priorité à attribuer au rapport dans MCP (ex: `LOW`, `MEDIUM`, `HIGH`).

### Exemple d'utilisation
```bash
nvyz push-to-mcp unified_report.sarif --mcp-url https://mcp.internal/api --encryption-key $NVC_ENC_KEY --tag "v1.0-release" --priority HIGH
```
