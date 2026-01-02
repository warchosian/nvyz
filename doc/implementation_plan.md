# Plan d'Implémentation pour "nvyz Code Forge"

Ce document décrit le plan d'implémentation détaillé pour le projet "nvyz Code Forge", basé sur l'analyse du document de spécifications `specs/CDC.txt`.

---

## **Analyse du projet "nvyz Code Forge"**

L'outil `nvyz` vise à être une plateforme complète d'analyse de code et de DevSecOps. Il utilise divers outils et bibliothèques existants pour fournir une analyse sémantique, des contrôles de sécurité, des métriques de qualité et des rapports.

**Fonctionnalités clés :**
*   **Extensibilité :** Architecture basée sur des plugins pour intégrer des outils comme CodeQL et SonarQube.
*   **Analyse sémantique :** Utilisation de `tree-sitter`.
*   **Sécurité :** Analyse de flux de données, recherche de secrets, intégration CodeQL.
*   **Qualité :** Complexité cognitive, couplage, intégration de règles SonarQube.
*   **Reporting :** Format SARIF, intégration avec un système interne "MCP", rapports HTML/PDF.
*   **Expérience utilisateur :** Sortie CLI riche, fonctionnalités interactives, binaires natifs.
*   **Intégration CI/CD :** Conçu pour les pipelines automatisés, analyses incrémentales, "quality gates".

---

## **Plan d'Implémentation (Phases)**

Ce plan propose une approche itérative et progressive pour le développement du projet.

#### **Phase 0 : Fondation et Configuration (Initial Setup & Core)**
*   **Objectif :** Mettre en place la structure de base du projet, les outils essentiels et le cadre des plugins.
    *   **Tâche 0.1 :** Finaliser la structure des dossiers et la configuration `poetry`. (Déjà en place)
    *   **Tâche 0.2 :** Set up Poetry for dependency management. (Déjà en place, `pyproject.toml` existe)
    *   **Tâche 0.3 :** Implement a basic CLI framework. (Déjà en place avec `src/app/cli.py`, sera étendu)
    *   **Tâche 0.4 :** Intégrer `rich` pour un affichage amélioré de la console (couleurs, barres de progression, emojis).
    *   **Tâche 0.5 :** Implémenter `python-dotenv` pour le chargement des variables d'environnement.
    *   **Tâche 0.6 :** Mettre en place `bandit` et `detect-secrets` pour l'auto-audit du code.
    *   **Tâche 0.7 :** Implémenter l'architecture de plugin de base (`AnalyzerPlugin`, `AnalysisResult` - structures de base).

#### **Phase 1 : Analyse Sémantique de Base et Reporting Initial**
*   **Objectif :** Fournir la capacité d'analyse sémantique fondamentale et générer des rapports SARIF simples.
    *   **Tâche 1.1 :** Intégrer `tree-sitter` et les grammaires de langage initiales.
    *   **Tâche 1.2 :** Développer la commande `nvyz semantic-scan` (parsing d'arbres syntaxiques, traversée).
        *   Prise en charge de `--auto-detect-lang`, `--threshold`, `--parallel`.
    *   **Tâche 1.3 :** Intégrer `sarif-om` pour la génération de rapports au format SARIF.
    *   **Tâche 1.4 :** Implémenter une version initiale de `nvyz report-generate` (sortie console et SARIF).
    *   **Tâche 1.5 :** Mettre en place une commande `nvyz push-to-mcp` (placeholder pour l'intégration MCP).

#### **Phase 2 : Fonctionnalités de Sécurité et Intégration CodeQL**
*   **Objectif :** Ajouter des capacités d'analyse de sécurité natives et intégrer CodeQL comme plugin.
    *   **Tâche 2.1 :** Développer la commande `nvyz secret-scan` (détection de secrets).
    *   **Tâche 2.2 :** Implémenter le `CodeQLPlugin` (appels au CLI `codeql`, conversion SARIF).
        *   Ajouter `codeql` comme dépendance optionnelle dans `pyproject.toml`.
    *   **Tâche 2.3 :** Implémenter la commande `nvyz codeql-scan`.
    *   **Tâche 2.4 :** Développer la commande `nvyz security-taint` (analyse des flux de données).

#### **Phase 3 : Métriques de Qualité et Intégration SonarQube**
*   **Objectif :** Calculer des métriques de qualité et intégrer SonarQube via un plugin.
    *   **Tâche 3.1 :** Développer la commande `nvyz semantic-metrics` (complexité cognitive, couplage).
    *   **Tâche 3.2 :** Implémenter le `SonarQubePlugin` (gestion de `sonar-scanner`, appels API, conversion SARIF).
        *   Ajouter `requests` et `xmltodict` comme dépendances optionnelles.
    *   **Tâche 3.3 :** Implémenter les commandes `nvyz sonar-scan`, `nvyz sonar-import`, `nvyz sonar-metrics`.
    *   **Tâche 3.4 :** Implémenter la commande `nvyz fuse-results` pour fusionner les rapports SARIF.

#### **Phase 4 : Fonctionnalités Avancées et CI/CD**
*   **Objectif :** Compléter les fonctionnalités clés pour l'automatisation et l'expérience utilisateur.
    *   **Tâche 4.1 :** Développer la commande `nvyz fix-issues` (suggestions de refactoring et application automatique).
    *   **Tâche 4.2 :** Implémenter la commande `nvyz ci-gate` pour les "quality gates" en CI.
    *   **Tâche 4.3 :** Implémenter l'analyse incrémentale avec `nvyz incremental-scan`.
    *   **Tâche 4.4 :** Développer la gestion de la configuration (`nvyz config-setup`) et le fichier `.nvyzrc`.
    *   **Tâche 4.5 :** Compléter les commandes `nvyz plugin enable/list`.

---

**Considérations Transversales pour toutes les phases :**
*   **Gestion des erreurs :** Reporting d'erreurs robuste.
*   **Tests :** Tests unitaires et d'intégration pour tous les composants.
*   **Documentation :** Documentation complète pour les commandes CLI et l'architecture.
*   **Optimisation des performances :** Utilisation de `joblib` pour la parallélisation.
*   **Déploiement :** Support pour `PyInstaller` pour les binaires natifs.

---

**Prochaine étape :**
Veuillez enregistrer le contenu ci-dessus dans un fichier nommé `implementation_plan.md` à l'intérieur du dossier `doc` (`doc/implementation_plan.md`).
