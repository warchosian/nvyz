# Prochaines Étapes - nvyz CLI

**Date de dernière mise à jour :** 2026-01-04
**Version actuelle :** 0.1.1a0
**Contributeur :** Équipe nvyz + Claude Code

---

## 🎯 Vision

nvyz CLI vise à devenir **l'outil de référence** pour l'analyse de sécurité multi-langages, combinant plusieurs outils (tree-sitter, CodeQL, SonarQube) dans une interface unifiée.

---

## 📋 Prochaines Étapes par Priorité

### 🔴 PRIORITÉ HAUTE (Court Terme - 1-2 mois)

#### 1. Support de Nouveaux Langages

**Objectif :** Étendre nvyz à d'autres langages populaires

**Langages à ajouter :**

- [ ] **JavaScript/TypeScript** ⭐ PRIORITAIRE
  - Installer `tree-sitter-javascript` et `tree-sitter-typescript`
  - Ajouter dans `treesitter.py` (lignes 102-113)
  - Créer `analyze_javascript_file()` dans `cli.py`
  - Patterns de sécurité : `eval()`, `innerHTML`, `document.write()`

- [ ] **C/C++**
  - Installer `tree-sitter-cpp`
  - Focus sur buffer overflows, memory leaks
  - Patterns : `strcpy`, `gets`, `malloc/free`

- [ ] **Go**
  - Installer `tree-sitter-go`
  - Focus sur goroutines, race conditions
  - Patterns : `unsafe`, `reflect`

- [ ] **Ruby**
  - Installer `tree-sitter-ruby`
  - Focus sur Rails security
  - Patterns : `eval`, `send`, `constantize`

**Fichiers à modifier :**
```python
# src/app/core/treesitter.py
try:
    import tree_sitter_javascript
    HAS_TS_JAVASCRIPT_PACKAGE = True
except ImportError:
    HAS_TS_JAVASCRIPT_PACKAGE = False

# Dans get_parser()
elif language_name.lower() == "javascript":
    if HAS_TS_JAVASCRIPT_PACKAGE:
        try:
            lang = Language(tree_sitter_javascript.language())
            print(f"Loaded JavaScript grammar")
        except Exception as e:
            print(f"Warning: {e}")
            return None
    else:
        print(f"Error: tree-sitter-javascript not installed")
        return None
```

---

#### 2. Amélioration de la Détection de Secrets

**Problème actuel :** Trop de faux positifs (39/40 pour "password")

**Solutions à implémenter :**

- [ ] **Whitelist de contextes sûrs**
  ```python
  SAFE_CONTEXTS = [
      r'\$_POST\[[\'"](password|passwd)[\'"]',  # $_POST['password'] est OK
      r'\$password\s*=\s*\$_',                   # $password = $_ est OK
      r'function.*\(\$password\)',                # function(...$password) est OK
      r'\'password\'\s*=>\s*\$',                 # 'password' => $ est OK
  ]
  ```

- [ ] **Analyse de contexte**
  - Détecter si "password" est un nom de variable vs une valeur
  - Vérifier si dans un formulaire HTML vs dans le code
  - Analyser l'entropie de la valeur, pas du mot-clé

- [ ] **Scoring de confiance**
  ```python
  # Au lieu de juste CRITICAL/HIGH
  confidence_score = calculate_confidence(context, entropy, position)
  # 0-30%: Probablement faux positif
  # 30-70%: À vérifier
  # 70-100%: Très probablement vrai
  ```

- [ ] **Patterns spécifiques par langage**
  - PHP : Ignorer `$_POST['password']`, `$_GET['password']`
  - JavaScript : Ignorer `req.body.password`, `formData.password`
  - Python : Ignorer `request.form['password']`

**Fichier à modifier :** `src/app/security/secret_scanner.py`

---

#### 3. Finaliser le Support --output pour Toutes les Commandes

**État actuel :**
- ✅ `secret-scan` : Support ajouté
- ✅ `chk-utf8` : Support ajouté
- ✅ `security-taint` : Support ajouté
- ✅ `semantic-scan` : Support existant
- ⚠️ `codeql-scan` : Support partiel (SARIF + MD)
- ❌ `fix-utf8` : Pas de support
- ❌ `sonar-scan` : Support partiel

**À faire :**

- [ ] Ajouter `--output` pour `fix-utf8`
  - Rapport des fichiers corrigés avec backup
  - Statistiques avant/après

- [ ] Standardiser le format de sortie
  - Tous les rapports doivent avoir un en-tête similaire
  - Section "Résumé" obligatoire
  - Section "Détails" avec les issues
  - Section "Recommandations"

- [ ] Ajouter format JSON pour intégration CI/CD
  ```bash
  nvyz secret-scan "**/*.py" --output report.json --format json
  ```

---

#### 4. Intégration SonarScanner

**Problème actuel :** SonarScanner CLI n'est pas installé, empêchant l'utilisation de `sonar-scan`

**Objectif :** Faciliter l'installation et l'utilisation de SonarScanner pour l'analyse de qualité de code

**Solutions à implémenter :**

- [ ] **Documentation d'installation SonarScanner**
  ```bash
  # Linux/macOS
  wget https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-5.0.1.3006.zip
  unzip sonar-scanner-cli-5.0.1.3006.zip
  export PATH=$PATH:$PWD/sonar-scanner-5.0.1.3006/bin

  # Windows
  # Télécharger depuis https://docs.sonarqube.org/latest/analyzing-source-code/scanners/sonarscanner/
  # Ajouter au PATH système
  ```

- [ ] **Vérification automatique de SonarScanner**
  ```python
  # Ajouter dans sonar_plugin.py
  def check_sonarscanner_installed():
      """Vérifie si sonar-scanner est disponible"""
      try:
          result = subprocess.run(['sonar-scanner', '--version'],
                                capture_output=True, text=True)
          return result.returncode == 0
      except FileNotFoundError:
          return False

  def suggest_installation():
      """Affiche des instructions d'installation si sonar-scanner manquant"""
      print("❌ sonar-scanner not found")
      print("\nInstallation options:")
      print("1. Download from: https://docs.sonarqube.org/latest/analyzing-source-code/scanners/sonarscanner/")
      print("2. Install via package manager:")
      print("   - Ubuntu/Debian: apt-get install sonar-scanner")
      print("   - macOS: brew install sonar-scanner")
      print("   - Windows: choco install sonarscanner")
  ```

- [ ] **Support de différentes instances SonarQube**

  **SonarCloud (gratuit pour projets open source) :**
  ```bash
  # Configuration dans sonar-project.properties
  sonar.organization=mon-organisation
  sonar.projectKey=mon-projet
  sonar.host.url=https://sonarcloud.io
  sonar.token=<SONARCLOUD_TOKEN>

  # Utilisation avec nvyz
  nvyz sonar-scan . --server https://sonarcloud.io --token $SONARCLOUD_TOKEN
  ```

  **SonarQube local :**
  ```bash
  # Démarrer SonarQube avec Docker
  docker run -d --name sonarqube -p 9000:9000 sonarqube:latest

  # Scanner avec nvyz
  nvyz sonar-scan . --server http://localhost:9000 --token <LOCAL_TOKEN>
  ```

  **SonarQube Enterprise :**
  ```bash
  nvyz sonar-scan . --server https://sonar.entreprise.com --token $SONAR_TOKEN
  ```

- [ ] **Améliorer les commandes sonar existantes**

  Actuellement nvyz a 3 commandes SonarQube :
  - `sonar-scan` : Scan local
  - `sonar-import` : Import depuis serveur SonarQube
  - `sonar-metrics` : Récupération de métriques

  **Améliorations à apporter :**
  ```python
  # Dans cli.py - améliorer sonar-scan
  parser_sonar_scan.add_argument('--install-check', action='store_true',
                                 help='Vérifier si sonar-scanner est installé')
  parser_sonar_scan.add_argument('--language',
                                 help='Langage du projet (php, python, java, etc.)')
  parser_sonar_scan.add_argument('--generate-config', action='store_true',
                                 help='Générer sonar-project.properties')
  parser_sonar_scan.add_argument('--quality-gate', action='store_true',
                                 help='Fail si Quality Gate échoue')
  ```

- [ ] **Génération automatique de sonar-project.properties**
  ```python
  def generate_sonar_config(project_dir, language, project_name):
      """Génère un fichier sonar-project.properties"""
      config = f"""# Generated by nvyz
  sonar.projectKey={project_name}
  sonar.projectName={project_name}
  sonar.projectVersion=1.0
  sonar.sources=src
  sonar.sourceEncoding=UTF-8
  sonar.language={language}

  # Exclusions
  sonar.exclusions=**/vendor/**,**/node_modules/**,**/tests/**

  # Tests
  sonar.tests=tests
  sonar.test.inclusions=**/*Test.php,**/*_test.py
  """
      with open(f"{project_dir}/sonar-project.properties", "w") as f:
          f.write(config)
  ```

- [ ] **Intégration avec Quality Gates**
  ```python
  def check_quality_gate(server_url, project_key, token):
      """Vérifie le statut du Quality Gate"""
      import requests

      url = f"{server_url}/api/qualitygates/project_status"
      params = {"projectKey": project_key}
      headers = {"Authorization": f"Bearer {token}"}

      response = requests.get(url, params=params, headers=headers)
      data = response.json()

      status = data['projectStatus']['status']
      if status == 'ERROR':
          print("❌ Quality Gate: FAILED")
          # Afficher les métriques qui ont échoué
          for condition in data['projectStatus']['conditions']:
              if condition['status'] == 'ERROR':
                  print(f"  - {condition['metricKey']}: {condition['actualValue']} "
                        f"(seuil: {condition['errorThreshold']})")
          return False
      else:
          print("✅ Quality Gate: PASSED")
          return True
  ```

**Fichier à modifier :** `src/app/plugins/sonar_plugin.py`

**Exemple d'utilisation améliorée :**
```bash
# Vérifier l'installation
nvyz sonar-scan --install-check

# Générer la configuration
nvyz sonar-scan . --generate-config --language php --project-name ttc

# Scanner avec Quality Gate
nvyz sonar-scan . \
  --server https://sonarcloud.io \
  --token $SONAR_TOKEN \
  --quality-gate \
  --output sonar-report.md

# Exit code 0 si Quality Gate OK, 1 sinon
```

**Intégration CI/CD :**
```yaml
# .gitlab-ci.yml
sonarqube-scan:
  stage: quality
  image: sonarsource/sonar-scanner-cli:latest
  script:
    - pip install nvyz
    - nvyz sonar-scan . \
        --server $SONAR_HOST_URL \
        --token $SONAR_TOKEN \
        --quality-gate \
        --output sonar-report.md
  artifacts:
    reports:
      sonarqube: sonar-report.json
  only:
    - main
    - merge_requests
```

---

### 🟡 PRIORITÉ MOYENNE (Moyen Terme - 2-4 mois)

#### 5. Intégration CI/CD

**Objectif :** Permettre l'exécution automatique de nvyz dans les pipelines

**GitHub Actions :**

```yaml
# .github/workflows/nvyz-security.yml
name: nvyz Security Scan

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
          pip install nvyz
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

      - name: Check Results
        run: |
          # Fail if critical issues found
          python -c "import json; data=json.load(open('secrets.json')); exit(1 if any(i['severity']=='CRITICAL' for i in data['issues']) else 0)"

      - name: Upload Reports
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: |
            secrets.json
            semantic.json
            taint.json
```

**GitLab CI :**

```yaml
# .gitlab-ci.yml
nvyz-security:
  stage: test
  image: python:3.11
  script:
    - pip install nvyz tree-sitter-python
    - nvyz secret-scan "**/*.py" --output secrets.json --format json
    - nvyz semantic-scan "**/*.py" --lang python --output semantic.json --format json
  artifacts:
    reports:
      security: secrets.json
    paths:
      - "*.json"
  allow_failure: false
```

---

#### 6. Quality Gates et Seuils Configurables

**Objectif :** Permettre de définir des seuils de qualité

**Fichier de configuration étendu :** `nvyz.yaml`

```yaml
quality_gates:
  # Fail the build if these thresholds are exceeded
  secrets:
    max_critical: 0      # No critical secrets allowed
    max_high: 2          # Max 2 high-severity secrets
    max_total: 10        # Max 10 total secrets

  semantic:
    max_file_lines: 800  # Fail if file > 800 lines
    max_complexity: 20   # Fail if cyclomatic complexity > 20
    max_functions: 30    # Fail if > 30 functions per file

  taint:
    max_medium: 5        # Max 5 medium taint issues
    max_high: 0          # No high taint issues

# Score calculation
scoring:
  weights:
    secrets: 0.3         # 30% of total score
    semantic: 0.2        # 20% of total score
    taint: 0.3          # 30% of total score
    codeql: 0.2         # 20% of total score

  passing_score: 70     # Minimum score to pass (out of 100)
```

**Commande :**
```bash
nvyz quality-gate --config nvyz.yaml --output report.json
# Exit code 0 if passed, 1 if failed
```

---

#### 7. Amélioration de l'Analyse Sémantique PHP

**Problèmes actuels :**
- Détecte seulement la longueur de fichier et le nombre de fonctions
- Pas d'analyse de complexité cyclomatique
- Pas de détection de code dupliqué

**À ajouter :**

- [ ] **Complexité cyclomatique**
  ```python
  def calculate_complexity(node):
      complexity = 1  # Base complexity
      # Count decision points
      if node.type in ('if_statement', 'switch_statement', 'while_statement',
                       'for_statement', 'foreach_statement', 'catch_clause'):
          complexity += 1
      # Count logical operators
      if node.type in ('binary_expression',):
          if node.text in (b'&&', b'||', b'and', b'or'):
              complexity += 1
      return complexity
  ```

- [ ] **Détection de code mort**
  - Fonctions jamais appelées
  - Variables déclarées mais jamais utilisées

- [ ] **Métriques de maintenabilité**
  - Indice de maintenabilité (0-100)
  - Dette technique en jours/homme

- [ ] **Détection de patterns anti-patterns PHP**
  - `eval()` usage
  - `extract()` sur données utilisateur
  - `$$` (variables variables) abuse
  - Suppression d'erreurs avec `@`

---

### 🟢 PRIORITÉ BASSE (Long Terme - 4-6 mois)

#### 8. Interface Web (Dashboard)

**Objectif :** Visualiser les résultats d'analyse dans un dashboard web

**Technologies :**
- Backend : Flask ou FastAPI
- Frontend : React ou Vue.js
- Base de données : SQLite ou PostgreSQL

**Fonctionnalités :**
- Upload de rapports SARIF/JSON
- Graphiques de tendances (évolution du score)
- Comparaison entre branches/commits
- Export PDF des rapports

---

#### 9. Support de Frameworks Spécifiques

**Objectif :** Analyse spécialisée pour frameworks populaires

**Frameworks à supporter :**

- [ ] **Laravel (PHP)**
  - Détection de mass assignment vulnerabilities
  - Validation de routes
  - Vérification CSRF tokens

- [ ] **Symfony (PHP)**
  - Security voters analysis
  - Service container security

- [ ] **Django (Python)**
  - ORM injection detection
  - Template auto-escaping verification

- [ ] **Express.js (JavaScript)**
  - Middleware security
  - Route parameter validation

---

#### 10. Plugin System

**Objectif :** Permettre aux utilisateurs d'ajouter leurs propres règles

**Architecture :**

```python
# plugins/custom_rule.py
from nvyz.core.plugin import AnalyzerPlugin, Issue, Severity

class CustomSecurityRule(AnalyzerPlugin):
    name = "custom-rule"
    description = "My custom security rule"

    def analyze(self, file_path, **kwargs):
        issues = []
        # Your custom logic here
        return AnalysisResult(issues=issues)
```

**Utilisation :**
```bash
nvyz plugin install ./plugins/custom_rule.py
nvyz custom-rule "**/*.php" --output report.md
```

---

#### 11. Support Multi-Repository

**Objectif :** Analyser plusieurs projets en une seule commande

**Configuration :** `workspace.yaml`

```yaml
workspace:
  name: "My Company Projects"
  repositories:
    - name: "api-backend"
      path: "/projects/api"
      language: "python"

    - name: "web-frontend"
      path: "/projects/web"
      language: "javascript"

    - name: "mobile-app"
      path: "/projects/mobile"
      language: "java"

scans:
  - secret-scan
  - semantic-scan
  - security-taint
```

**Commande :**
```bash
nvyz workspace scan --config workspace.yaml --output-dir ./reports/
```

---

## 🐛 Bugs Connus à Corriger

### Issues Critiques

1. **CodeQL ne supporte pas PHP**
   - Workaround : Utiliser SonarQube ou PHPStan
   - Long terme : Contribuer à CodeQL pour ajouter support PHP

2. **Encodage Windows vs Unix**
   - Les chemins Windows avec backslashes causent des problèmes
   - Solution : Normaliser tous les chemins avec `pathlib.Path`

3. **Unicode dans la console Windows**
   - Les emojis ne s'affichent pas correctement
   - Solution : Détecter l'OS et adapter l'output

---

## 📊 Métriques de Succès

**Objectifs pour v0.2.0 :**
- ✅ Support de 5+ langages
- ✅ 90%+ de précision (moins de faux positifs)
- ✅ Intégration CI/CD complète
- ✅ 1000+ installations

**Objectifs pour v1.0.0 :**
- ✅ Support de 10+ langages
- ✅ Dashboard web fonctionnel
- ✅ Plugin system stable
- ✅ 10,000+ installations
- ✅ Documentation complète

---

## 🤝 Comment Contribuer

**Pour ajouter un nouveau langage :**

1. Installer le package tree-sitter correspondant
   ```bash
   pip install tree-sitter-<language>
   ```

2. Modifier `src/app/core/treesitter.py` :
   - Ajouter l'import
   - Ajouter le cas dans `get_parser()`

3. Modifier `src/app/cli.py` :
   - Créer `analyze_<language>_file()`
   - Ajouter le cas dans la boucle d'analyse

4. Tester avec des fichiers réels

5. Documenter les patterns de sécurité spécifiques

**Pour ajouter une nouvelle règle de sécurité :**

1. Identifier le pattern dangereux
2. Créer un test case
3. Implémenter la détection dans le module approprié
4. Ajouter la documentation

---

## 📚 Ressources

**Documentation :**
- tree-sitter : https://tree-sitter.github.io/
- CodeQL : https://codeql.github.com/
- SonarQube : https://docs.sonarqube.org/
- SARIF : https://sarifweb.azurewebsites.net/

**Exemples de règles de sécurité :**
- OWASP Top 10 : https://owasp.org/www-project-top-ten/
- CWE : https://cwe.mitre.org/
- SANS Top 25 : https://www.sans.org/top25-software-errors/

---

## 📅 Roadmap Timeline

```
Q1 2026 (Jan-Mar)
├── ✅ Support PHP (FAIT)
├── ✅ Support --output étendu (FAIT)
├── [ ] Support JavaScript/TypeScript
└── [ ] Amélioration détection secrets

Q2 2026 (Apr-Jun)
├── [ ] Support Go, Ruby, C/C++
├── [ ] Intégration CI/CD complète
├── [ ] Quality Gates
└── [ ] Format JSON pour tous les rapports

Q3 2026 (Jul-Sep)
├── [ ] Dashboard web (beta)
├── [ ] Plugin system
└── [ ] Support frameworks populaires

Q4 2026 (Oct-Dec)
├── [ ] Support multi-repository
├── [ ] Documentation complète
├── [ ] Release v1.0.0
└── [ ] Conference presentations
```

---

## 💬 Feedback et Support

**Rapporter un bug :**
https://github.com/anthropics/claude-code/issues

**Demander une fonctionnalité :**
https://github.com/anthropics/claude-code/discussions

**Contribuer :**
https://github.com/anthropics/claude-code/pulls

---

**Dernière mise à jour :** 2026-01-04
**Prochaine révision prévue :** 2026-02-01
**Maintenu par :** Équipe nvyz + Communauté

🚀 **Merci de contribuer à faire de nvyz le meilleur outil d'analyse de sécurité !**
