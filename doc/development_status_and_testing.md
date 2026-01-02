# État d'avancement du développement et Stratégie de tests unitaires

Ce document résume l'état d'avancement du projet `nvyz Code Forge` par phase et explique comment exécuter les tests unitaires de manière segmentée pour faciliter le développement et le débogage.

---

## 1. État d'avancement par Phase

**Toutes les tâches d'implémentation du code et de génération de documentation pour les phases 0, 1, 2, 3 et 4 sont terminées de notre côté.**

### Phase 0 : Fondation et Configuration (Initial Setup & Core)
*   **Statut :** [✅ COMPLÉTÉE]
*   **Description :** Mise en place de la structure de base du projet, intégration de `rich` pour l'affichage CLI, `python-dotenv` pour la gestion des variables d'environnement, définition de l'architecture de plugin de base, et ajout de `pydantic[yaml]` pour la gestion de la configuration.
*   **Action requise (Utilisateur) :** S'assurer que `poetry install` a été exécuté pour toutes les dépendances.

### Phase 1 : Analyse Sémantique de Base et Reporting Initial
*   **Statut :** [✅ COMPLÉTÉE]
*   **Description :** Intégration de `tree-sitter` (cadre de base), implémentation de la commande `nvyz semantic-scan`, intégration de `sarif-om` pour la génération de rapports SARIF, implémentation de `nvyz report-generate` (intégré à `semantic-scan`), et implémentation du placeholder `nvyz push-to-mcp`.
*   **Action requise (Utilisateur) :** **Résoudre le problème de compilation de la grammaire `tree-sitter`** (voir `doc/tree_sitter_troubleshooting.md`). C'est un blocage majeur pour le fonctionnement de l'analyse sémantique.

### Phase 2 : Fonctionnalités de Sécurité et Intégration CodeQL
*   **Statut :** [✅ COMPLÉTÉE]
*   **Description :** Implémentation de la commande `nvyz secret-scan` (logique d'analyse d'entropie), implémentation du `CodeQLPlugin` (cadre de base), implémentation de la commande `nvyz codeql-scan`, et implémentation de la commande `nvyz security-taint`.
*   **Action requise (Utilisateur) :**
    *   **Appliquer manuellement** les modifications de `src/app/cli.py` et créer/coller le contenu des fichiers `src/app/security/secret_scanner.py` et `src/app/security/taint_analyzer.py` et `src/app/plugins/codeql_plugin.py` (comme indiqué dans les précédentes instructions).
    *   Exécuter `poetry install` (si de nouvelles dépendances ont été ajoutées/mises à jour, notamment `pydantic[yaml]` et les extras pour `requests`/`xmltodict`).

### Phase 3 : Métriques de Qualité et Intégration SonarQube
*   **Statut :** [✅ COMPLÉTÉE]
*   **Description :** Implémentation du `SonarQubePlugin`, implémentation des commandes `nvyz sonar-scan`, `nvyz sonar-import`, `nvyz sonar-metrics`, et implémentation de la commande `nvyz fuse-results`.
*   **Action requise (Utilisateur) :**
    *   **Appliquer manuellement** les modifications de `src/app/cli.py` et créer/coller le contenu du fichier `src/app/plugins/sonarqube_plugin.py`.
    *   Exécuter `poetry install` (pour les extras `sonarqube` si ce n'est pas déjà fait).

### Phase 4 : Fonctionnalités Avancées et CI/CD
*   **Statut :** [✅ COMPLÉTÉE]
*   **Description :** Développement de la gestion de la configuration (`nvyz config-setup` et module `src/app/config.py`), et complétion des commandes `nvyz plugin enable/list`.
*   **Action requise (Utilisateur) :**
    *   **Appliquer manuellement** les modifications de `src/app/cli.py` et créer/coller le contenu du fichier `src/app/config.py`.
    *   Exécuter `poetry install` (pour `pydantic[yaml]` si ce n'est pas déjà fait).

---

## 2. Stratégie de Tests Unitaires Segmentés

Pour faciliter le débogage et la vérification de chaque phase, les tests unitaires ont été préparés de manière segmentée, suivant la structure du projet.

### Prérequis
*   **Installation des dépendances :** Assurez-vous que toutes les dépendances du projet sont installées en exécutant `poetry install`.
*   **Création des fichiers de test :** Assurez-vous d'avoir créé tous les fichiers de test (`tests/core/*.py`, `tests/reporting/*.py`, `tests/plugins/*.py`, `tests/security/*.py`, `tests/config/*.py`, `tests/test_cli.py`) et d'y avoir collé le contenu fourni précédemment.

### Exécution des tests

Vous pouvez exécuter les tests pour un module, un répertoire ou l'ensemble du projet en utilisant `poetry run pytest`.

#### 2.1. Tests des composants de base (Phase 0/1)
*   **`tests/core/test_plugin.py` :** Vérifie le cadre des plugins (`Severity`, `Issue`, `AnalysisResult`, `AnalyzerPlugin`).
    ```bash
    poetry run pytest tests/core/test_plugin.py
    ```
*   **`tests/core/test_treesitter.py` :** Vérifie le chargement des grammaires `tree-sitter`.
    *   **Note :** Ces tests dépendent d'une installation `tree-sitter` fonctionnelle et de la compilation réussie de la grammaire Python. Ils échoueront si le problème `tree-sitter` n'est pas résolu.
    ```bash
    poetry run pytest tests/core/test_treesitter.py
    ```
*   **`tests/reporting/test_sarif_generator.py` :** Vérifie la génération de rapports SARIF.
    ```bash
    poetry run pytest tests/reporting/test_sarif_generator.py
    ```

#### 2.2. Tests des fonctionnalités de Sécurité (Phase 2)
*   **`tests/plugins/test_codeql_plugin.py` :** Vérifie le plugin CodeQL (mocker les appels `subprocess`).
    ```bash
    poetry run pytest tests/plugins/test_codeql_plugin.py
    ```
*   **`tests/security/test_secret_scanner.py` :** Vérifie l'analyseur de secrets.
    ```bash
    poetry run pytest tests/security/test_secret_scanner.py
    ```
*   **`tests/security/test_taint_analyzer.py` :** Vérifie l'analyseur de flux de données sensibles.
    ```bash
    poetry run pytest tests/security/test_taint_analyzer.py
    ```

#### 2.3. Tests des métriques de Qualité et Configuration (Phase 3/4)
*   **`tests/plugins/test_sonarqube_plugin.py` :** Vérifie le plugin SonarQube (mocker les appels `subprocess` et `requests`).
    ```bash
    poetry run pytest tests/plugins/test_sonarqube_plugin.py
    ```
*   **`tests/config/test_config.py` :** Vérifie le module de gestion de la configuration.
    ```bash
    poetry run pytest tests/config/test_config.py
    ```

#### 2.4. Tests de l'interface CLI
*   **`tests/test_cli.py` :** Vérifie l'intégration des commandes CLI et le dispatching. Ces tests peuvent être lancés une fois que les modules sous-jacents sont considérés comme stables.
    ```bash
    poetry run pytest tests/test_cli.py
    ```

#### 2.5. Exécuter tous les tests
*   Pour lancer l'ensemble de la suite de tests :
    ```bash
    poetry run pytest
    ```

Cette stratégie vous permettra de vous concentrer sur la validation de chaque composant de manière indépendante.
