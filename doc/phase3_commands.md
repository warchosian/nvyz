# Documentation des commandes CLI de Phase 3

Ce document détaille les commandes CLI liées à l'intégration SonarQube et aux métriques de qualité, développées durant la Phase 3 du projet "nvyz Code Forge", ainsi que leurs arguments respectifs.

---

## 1. `nvyz sonar-scan`

### Description
Exécute une analyse locale avec SonarScanner (sans nécessiter de serveur SonarQube distant actif). Les résultats sont convertis et peuvent être sauvegardés au format SARIF.

### Syntaxe
`nvyz sonar-scan <path> [--offline] [--rules <ruleset>] [--sonar-project-file <file>] [--output <file_path>]`

### Arguments

#### Arguments positionnels
*   `<path>` (obligatoire, multiple)
    *   Chemins ou motifs (globs) des fichiers/répertoires à analyser avec SonarScanner.
    *   Exemple : `./src`

#### Arguments optionnels
*   `--offline` (flag)
    *   Indique d'exécuter SonarScanner en mode hors ligne, sans communication avec un serveur SonarQube.
*   `--rules <ruleset>`
    *   Spécifie l'ensemble de règles SonarQube à utiliser pour l'analyse locale (ex: `security-hotspots`).
*   `--sonar-project-file <file>`
    *   Chemin vers le fichier `sonar-project.properties` contenant la configuration spécifique du projet pour SonarScanner.
*   `--output <file_path>`
    *   Chemin du fichier où le rapport d'analyse SARIF résultant doit être enregistré.

### Exemple d'utilisation
```bash
nvyz sonar-scan ./my_python_app --offline --rules python-security --output sonar_results.sarif
```

---

## 2. `nvyz sonar-import`

### Description
Importe les issues et les métriques d'un projet depuis un serveur SonarQube existant via son API. Les résultats sont convertis et peuvent être sauvegardés au format SARIF.

### Syntaxe
`nvyz sonar-import --project-key <key> --server-url <url> [--token <token>] [--quality-gate <gate_name>] [--output <file_path>]`

### Arguments

#### Arguments optionnels
*   `--project-key <key>` (obligatoire)
    *   La clé unique du projet SonarQube à importer.
*   `--server-url <url>` (obligatoire)
    *   L'URL de base du serveur SonarQube (ex: `https://sonar.entreprise.com`).
*   `--token <token>`
    *   Token d'authentification pour l'accès à l'API SonarQube. Idéalement fourni via une variable d'environnement (ex: `SONAR_TOKEN`).
*   `--quality-gate <gate_name>`
    *   Nom de la Quality Gate SonarQube à évaluer.
*   `--output <file_path>`
    *   Chemin du fichier où le rapport SARIF des issues importées doit être enregistré.

### Exemple d'utilisation
```bash
nvyz sonar-import --project-key my-backend --server-url https://sonar.mycompany.com --token $SONAR_API_TOKEN --output sonar_api_issues.sarif
```

---

## 3. `nvyz sonar-metrics`

### Description
Calcule des métriques de dette technique et de qualité via l'intégration des règles SonarQube, en se basant sur un profil de qualité spécifié.

### Syntaxe
`nvyz sonar-metrics <path> --quality-profile <profile_name> [--output <file_path>]`

### Arguments

#### Arguments positionnels
*   `<path>` (obligatoire, multiple)
    *   Chemins ou motifs (globs) des fichiers/répertoires sur lesquels calculer les métriques.

#### Arguments optionnels
*   `--quality-profile <profile_name>` (obligatoire)
    *   Le nom du profil de qualité SonarQube à utiliser pour le calcul des métriques (ex: `enterprise-python`).
*   `--output <file_path>`
    *   Chemin du fichier où les métriques calculées doivent être enregistrées, au format CSV.

### Exemple d'utilisation
```bash
nvyz sonar-metrics ./src --quality-profile "Python Security" --output metrics.csv
```
