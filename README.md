# nvyz - Multi-Language Security Analysis CLI

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.1a0-orange)](CHANGELOG.md)

**nvyz** est un outil d'analyse de sécurité et de qualité de code en ligne de commande qui combine plusieurs technologies d'analyse statique (tree-sitter, CodeQL, SonarQube) dans une interface unifiée.

## ✨ Fonctionnalités

### 🔒 Analyse de Sécurité
- **Secret Scanning** : Détection de secrets hardcodés (mots de passe, tokens API, clés privées)
- **Taint Analysis** : Analyse de flux de données pour détecter les vulnérabilités d'injection (SQL, XSS, Command Injection)
- **CodeQL Integration** : Analyse sémantique avancée avec les requêtes CodeQL
- **SonarQube Plugin** : Intégration avec SonarQube pour l'analyse continue

### 📊 Analyse de Qualité
- **Semantic Analysis** : Détection de code complexe, fichiers trop longs, fonctions excessives
- **Encoding Verification** : Vérification de l'encodage UTF-8 des fichiers
- **SARIF Reports** : Génération de rapports au format SARIF pour intégration CI/CD

### 🌐 Support Multi-Langages
- ✅ **Python** - Support complet
- ✅ **Java** - Support complet
- ✅ **PHP** - Support complet (nouveau !)
- 🔄 **JavaScript/TypeScript** - En développement
- 🔄 **Go, Ruby, C/C++** - Planifiés

## 🚀 Installation

### Prérequis
- Python 3.10 ou supérieur

### Installation rapide (recommandée)

**Option 1 : Installation depuis la wheel (plus rapide)**

```bash
# Télécharger la wheel depuis GitHub Releases
# https://github.com/warchosian/nvyz/releases

# Installer la wheel
pip install nvyz-0.1.1a0-py3-none-any.whl

# Installer les grammaires tree-sitter nécessaires
pip install tree-sitter-python tree-sitter-java tree-sitter-php
```

**Option 2 : Installation depuis le dépôt**

```bash
# Cloner et installer en une commande
git clone https://github.com/warchosian/nvyz.git
cd nvyz
pip install dist/nvyz-0.1.1a0-py3-none-any.whl

# Installer les grammaires tree-sitter
pip install tree-sitter-python tree-sitter-java tree-sitter-php
```

### Installation pour développeurs (avec Poetry)

```bash
# Cloner le dépôt
git clone https://github.com/warchosian/nvyz.git
cd nvyz

# Installer les dépendances (inclut les outils de développement)
poetry install

# Installer les grammaires tree-sitter
pip install tree-sitter-python tree-sitter-java tree-sitter-php

# Activer l'environnement virtuel
poetry shell

# Vérifier l'installation
nvyz --version
```

**Note pour les développeurs :**
- Utilisez `poetry run cz commit` pour des commits standardisés
- Utilisez `poetry run cz bump` pour gérer les versions
- Lancez `poetry build` pour créer une nouvelle wheel

## 📖 Utilisation

### Commandes Principales

#### 1. Secret Scan - Détection de Secrets

```bash
# Scanner un projet PHP pour les secrets
nvyz secret-scan "src/**/*.php" --output secrets.md

# Scanner avec seuil d'entropie personnalisé
nvyz secret-scan "**/*.py" --entropy-threshold 4.5 --output report.md

# Format JSON pour CI/CD
nvyz secret-scan "**/*.js" --output secrets.json --format json
```

**Détecte :**
- Mots de passe hardcodés
- Tokens API et clés d'accès
- Clés privées SSH/GPG
- Secrets AWS, Azure, Google Cloud
- Chaînes à haute entropie (possibles secrets encodés)

#### 2. Semantic Scan - Analyse Sémantique

```bash
# Analyser la qualité du code PHP
nvyz semantic-scan "src/**/*.php" --lang php --output semantic.md

# Analyser du code Python
nvyz semantic-scan "**/*.py" --lang python --output report.md
```

**Détecte :**
- Fichiers trop longs (> 400/600 lignes)
- Trop de fonctions par fichier (> 25)
- Complexité excessive (à venir)
- Code dupliqué (à venir)

#### 3. Taint Analysis - Flux de Données

```bash
# Analyser les vulnérabilités d'injection PHP
nvyz security-taint "src/**/*.php" \
  --sensitive-patterns "\$_GET" "\$_POST" "\$_REQUEST" \
  --entry-points "index.php" "router.php" \
  --sinks "eval" "exec" "system" \
  --output taint-report.md

# Analyser les vulnérabilités Python
nvyz security-taint "**/*.py" \
  --sensitive-patterns "request.GET" "request.POST" \
  --entry-points "views.py" \
  --sinks "eval" "exec" "__import__" \
  --output taint.md
```

**Détecte :**
- Injection SQL
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Code Injection

#### 4. UTF-8 Encoding Check

```bash
# Vérifier l'encodage des fichiers
nvyz chk-utf8 "**/*.md" --output encoding-report.md

# Corriger automatiquement les fichiers non-UTF8
nvyz fix-utf8 "**/*.txt"
```

#### 5. CodeQL Scan

```bash
# Scanner avec CodeQL (Python/Java)
nvyz codeql-scan . --lang python --query-suite security-extended

# Générer un rapport SARIF
nvyz codeql-scan . --lang java \
  --query-suite security-and-quality \
  --sarif-output results.sarif
```

**Note :** CodeQL ne supporte actuellement pas PHP. Utilisez SonarQube ou PHPStan pour PHP.

#### 6. SonarQube Integration

```bash
# Scanner avec SonarQube local
nvyz sonar-scan . --server http://localhost:9000 --token <TOKEN>

# Scanner avec SonarCloud
nvyz sonar-scan . \
  --server https://sonarcloud.io \
  --token $SONARCLOUD_TOKEN \
  --output sonar-report.md
```

## 📋 Exemples d'Utilisation Réels

### Analyser une Application PHP (Projet TTC)

```bash
# 1. Scanner les secrets
nvyz secret-scan "src/**/*.php" --output 01-secrets.md

# 2. Analyser la qualité du code
nvyz semantic-scan "src/**/*.php" --lang php --output 02-semantic.md

# 3. Analyser les flux de données
nvyz security-taint "src/**/*.php" \
  --sensitive-patterns "\$_GET" "\$_POST" "\$_COOKIE" \
  --entry-points "index.php" \
  --sinks "eval" "exec" "system" "shell_exec" \
  --output 03-taint.md

# 4. Vérifier l'encodage
nvyz chk-utf8 "**/*.md" --output 04-encoding.md
```

**Résultats :**
- 137 fichiers PHP analysés
- 40 détections de secrets (39 faux positifs)
- 22 issues de qualité de code
- 0 vulnérabilité de flux de données
- Score : 72/100 (Grade C)

### Intégration CI/CD

#### GitHub Actions

```yaml
# .github/workflows/nvyz-security.yml
name: Security Analysis

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install nvyz
        run: |
          pip install poetry
          git clone https://github.com/warchosian/nvyz.git
          cd nvyz
          poetry install
          poetry build
          pip install dist/*.whl
          pip install tree-sitter-python tree-sitter-php

      - name: Run Security Scans
        run: |
          nvyz secret-scan "**/*.py" --output secrets.json --format json
          nvyz semantic-scan "**/*.py" --lang python --output semantic.json --format json
          nvyz security-taint "**/*.py" \
            --sensitive-patterns "request.GET" "request.POST" \
            --entry-points "views.py" \
            --sinks "eval" "exec" \
            --output taint.json --format json

      - name: Upload Reports
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: "*.json"
```

#### GitLab CI

```yaml
# .gitlab-ci.yml
nvyz-security:
  stage: test
  image: python:3.11
  script:
    - pip install poetry
    - git clone https://github.com/warchosian/nvyz.git
    - cd nvyz && poetry install && poetry build && cd ..
    - pip install nvyz/dist/*.whl tree-sitter-python tree-sitter-php
    - nvyz secret-scan "**/*.py" --output secrets.json --format json
    - nvyz semantic-scan "**/*.py" --lang python --output semantic.json --format json
  artifacts:
    reports:
      security: secrets.json
    paths:
      - "*.json"
  allow_failure: false
```

## ⚙️ Configuration

### Fichier de Configuration (nvyz.yaml)

```yaml
# Configuration nvyz
analysis:
  # Langages à analyser
  languages:
    - python
    - java
    - php

  # Exclusions
  exclude:
    - "**/vendor/**"
    - "**/node_modules/**"
    - "**/venv/**"
    - "**/.git/**"

# Secret scanning
secrets:
  entropy_threshold: 4.5
  patterns:
    - password
    - secret
    - api_key
    - token
    - private_key

# Semantic analysis
semantic:
  max_file_lines: 600
  max_functions_per_file: 25

# Taint analysis
taint:
  sensitive_patterns:
    php:
      - "$_GET"
      - "$_POST"
      - "$_REQUEST"
      - "$_COOKIE"
    python:
      - "request.GET"
      - "request.POST"
      - "request.args"

  sinks:
    php:
      - "eval"
      - "exec"
      - "system"
      - "shell_exec"
      - "passthru"
    python:
      - "eval"
      - "exec"
      - "__import__"
      - "compile"

# CodeQL
codeql:
  default_suite: security-extended
```

## 📊 Formats de Sortie

nvyz supporte plusieurs formats de sortie :

- **Markdown (.md)** : Rapports lisibles pour documentation
- **Text (.txt)** : Rapports simples
- **JSON (.json)** : Pour intégration CI/CD et parsing automatique
- **SARIF (.sarif)** : Standard pour outils d'analyse statique

## 🗺️ Roadmap

### Q1 2026 (Jan-Mar)
- ✅ Support PHP complet
- ✅ Support `--output` étendu pour toutes les commandes
- ✅ Argument `--lang` pour CodeQL
- 🔄 Support JavaScript/TypeScript
- 🔄 Amélioration détection de secrets (réduction faux positifs)

### Q2 2026 (Apr-Jun)
- 🔄 Support Go, Ruby, C/C++
- 🔄 Quality Gates configurables
- 🔄 Format JSON pour tous les rapports
- 🔄 Intégration CI/CD complète

### Q3 2026 (Jul-Sep)
- 🔄 Dashboard web (beta)
- 🔄 Plugin system
- 🔄 Support frameworks (Laravel, Django, Express)

### Q4 2026 (Oct-Dec)
- 🔄 Support multi-repository
- 🔄 Documentation complète
- 🔄 Release v1.0.0

Voir [NEXT-STEPS.md](NEXT-STEPS.md) pour plus de détails.

## 🤝 Contribution

Les contributions sont les bienvenues ! Voici comment contribuer :

### Ajouter un Nouveau Langage

1. Installer le package tree-sitter correspondant
   ```bash
   pip install tree-sitter-<language>
   ```

2. Modifier `src/app/core/treesitter.py`
   ```python
   try:
       import tree_sitter_<language>
       HAS_TS_<LANGUAGE>_PACKAGE = True
   except ImportError:
       HAS_TS_<LANGUAGE>_PACKAGE = False

   # Dans get_parser()
   elif language_name.lower() == "<language>":
       if HAS_TS_<LANGUAGE>_PACKAGE:
           lang = Language(tree_sitter_<language>.language())
   ```

3. Créer la fonction d'analyse dans `src/app/cli.py`
   ```python
   def analyze_<language>_file(file_path, parser):
       # Votre logique d'analyse
       pass
   ```

4. Tester et documenter

### Guidelines de Contribution

- Suivre les conventions de code Python (PEP 8)
- Ajouter des tests pour les nouvelles fonctionnalités
- Mettre à jour la documentation
- Utiliser `poetry run cz commit` pour les commits standardisés

## 📝 Licence

Ce projet est sous licence MIT. Voir [LICENSE](LICENSE) pour plus de détails.

## 📚 Documentation

- [CHANGELOG.md](CHANGELOG.md) - Historique des versions
- [NEXT-STEPS.md](NEXT-STEPS.md) - Roadmap et prochaines étapes
- [PROCEDURE_ANALYSE_COMPLETE_CLI.md](doc/PROCEDURE_ANALYSE_COMPLETE_CLI.md) - Guide d'analyse complète

## 🙏 Remerciements

- **tree-sitter** - Parsers de code source
- **CodeQL** - Analyse sémantique
- **SonarQube** - Qualité de code
- **Communauté open source** - Pour les contributions et le support

## 📞 Support

- 🐛 **Rapporter un bug** : [GitHub Issues](https://github.com/warchosian/nvyz/issues)
- 💡 **Demander une fonctionnalité** : [GitHub Discussions](https://github.com/warchosian/nvyz/discussions)
- 📧 **Contact** : [Créer une issue](https://github.com/warchosian/nvyz/issues/new)

---

**Fait avec ❤️ par la communauté nvyz**

🚀 **Sécurisez votre code avec nvyz !**
