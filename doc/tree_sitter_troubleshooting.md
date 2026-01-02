# État des lieux : Problème de compilation de la grammaire Tree-sitter

## Contexte
Le projet `nvyz` utilise `tree-sitter` pour l'analyse sémantique du code. Pour fonctionner, `tree-sitter` nécessite des grammaires compilées spécifiques à chaque langage (par exemple, `python.dll` pour Python sur Windows). Un script `build_grammar.py` a été créé pour automatiser cette compilation.

## Problème rencontré
Lors de l'exécution du script `build_grammar.py` (même après plusieurs tentatives d'adaptation et de robustesse de ce script), l'erreur suivante est survenue de manière persistante :

```
AttributeError: type object 'tree_sitter.Language' has no attribute 'build_library'
```
Puis, la version la plus robuste du script a renvoyé :
```
Error: Could not find a compatible 'build_library' function for your tree-sitter version after trying all known APIs.
Please ensure your 'tree-sitter' Python package is correctly installed and compatible.
...
AttributeError: module 'tree_sitter' has no attribute '__version__'
```

## Analyse du problème
Ces erreurs indiquent un problème fondamental avec l'installation du paquet Python `tree-sitter` dans votre environnement (`conda_ai10`).

1.  **`AttributeError: ... has no attribute 'build_library'` :**
    La fonction `build_library` (qui compile les grammaires) a vu son API changer plusieurs fois au cours des différentes versions de la bibliothèque Python `tree-sitter`. Le script `build_grammar.py` a été adapté pour tenter d'appeler cette fonction en utilisant toutes les signatures connues (comme `tree_sitter.Language.build_library`, `Language.build_library`, ou `tree_sitter.build_library`). Le fait qu'aucune de ces tentatives n'ait fonctionné suggère que votre version de `tree-sitter` est soit :
    *   Mal installée ou corrompue.
    *   Une version intermédiaire dont l'API pour `build_library` est inconnue ou cassée.

2.  **`AttributeError: module 'tree_sitter' has no attribute '__version__'` :**
    Cette erreur est encore plus préoccupante. Le fait que l'attribut `__version__` (qui devrait toujours être présent sur un module Python bien formé) soit manquant indique très fortement que l'installation du paquet `tree_sitter` est corrompue ou incomplète.

En résumé, l'environnement Python n'arrive pas à charger ou à utiliser la bibliothèque `tree-sitter` de manière cohérente.

## Solution proposée (Réinstallation propre)

Pour résoudre ce problème, la solution la plus fiable est de **désinstaller complètement et de réinstaller proprement le paquet `tree-sitter`** dans votre environnement Poetry.

**Étapes à suivre :**

1.  **Désinstaller `tree-sitter` :**
    ```bash
    poetry remove tree-sitter
    ```

2.  **Installer la dernière version compatible de `tree-sitter` :**
    *   La spécification du projet (`pyproject.toml`) vise `tree-sitter = "^0.25.2"`. Vous pouvez tenter de la forcer.
    ```bash
    poetry add tree-sitter@latest
    # Ou, si 'latest' cause toujours des problèmes, vous pouvez tenter une version spécifique
    # poetry add tree-sitter@0.21.0
    ```
    *(Note : la version `0.21.0` de `tree-sitter` est souvent stable pour la compilation de grammaire avec des grammaires récentes).*

3.  **Assurer une installation propre :**
    ```bash
    poetry install
    ```
    *(Ceci va réinstaller toutes les dépendances du projet, y compris la nouvelle version de `tree-sitter`, et s'assurer qu'elles sont correctement liées à l'environnement virtuel de Poetry).*

4.  **Re-compiler la grammaire :**
    Après la réinstallation, relancez le script de compilation de la grammaire :
    ```bash
    poetry run python build_grammar.py
    ```
    Cette fois, si `tree-sitter` est correctement installé, le script devrait réussir à compiler la grammaire sans erreur.

5.  **Relancer l'analyse sémantique :**
    Enfin, tentez à nouveau votre commande d'analyse sémantique :
    ```bash
    nvyz semantic-scan G:\WarchoLife\WarchoDevplace\Gitlab_Git\formation-ecologie\app  --lang python --threshold high --output results.sarif
    ```

Si malgré ces étapes, vous rencontrez toujours des problèmes, il se peut qu'il y ait une incompatibilité plus profonde avec votre environnement (système d'exploitation, version de Python, ou outils de compilation C/C++). Dans ce cas, il serait nécessaire de consulter la documentation officielle de `tree-sitter` pour l'installation manuelle ou de rechercher des solutions spécifiques à votre configuration.
