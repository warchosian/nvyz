import os # New import
from pathlib import Path
from typing import Optional

from tree_sitter import Language, Parser

# Try to import tree_sitter_python (tree-sitter 0.25.x)
try:
    import tree_sitter_python
    HAS_TS_PYTHON_PACKAGE = True
except ImportError:
    HAS_TS_PYTHON_PACKAGE = False

# Try to import tree_sitter_java
try:
    import tree_sitter_java
    HAS_TS_JAVA_PACKAGE = True
except ImportError:
    HAS_TS_JAVA_PACKAGE = False

# Try to import tree_sitter_php
try:
    import tree_sitter_php
    HAS_TS_PHP_PACKAGE = True
except ImportError:
    HAS_TS_PHP_PACKAGE = False

# Assume grammars are located in a 'grammars' directory at the project root
# For a more robust solution, this path might be configurable or handled by a build process
GRAMMARS_DIR = Path(__file__).parent.parent.parent / "grammars"
BUILD_DIR = Path(__file__).parent.parent.parent.parent / "build" / "grammars"

# Determine the correct file extension for the compiled library based on OS
if os.name == "nt":  # Windows
    LIB_EXTENSION = ".dll"
elif os.name == "posix": # Linux and other Unix-like systems (including macOS)
    LIB_EXTENSION = ".so"
else: # Fallback or other systems
    LIB_EXTENSION = ".so" # Default to .so for unknown systems.

PYTHON_LANGUAGE_PATH = BUILD_DIR / f"python{LIB_EXTENSION}"


def load_language_grammar(language_name: str, library_path: Path) -> Optional[Language]:
    """
    Loads a pre-compiled Tree-sitter language grammar.

    Args:
        language_name: The name of the language (e.g., "python").
        library_path: The path to the compiled grammar shared library (.so, .dll, .dylib).

    Returns:
        A tree_sitter.Language object if successful, None otherwise.
    """
    if not library_path.is_file():
        # In a real setup, this would trigger a compilation step or error
        print(f"Error: Compiled grammar not found for {language_name} at {library_path}")
        return None
    try:
        # The first argument is the path to the compiled grammar
        # The second argument is the name of the language in the grammar's 'name' field
        return Language(str(library_path), language_name)
    except Exception as e:
        print(f"Error loading grammar for {language_name} from {library_path}: {e}")
        return None

def get_parser(language_name: str) -> Optional[Parser]:
    """
    Returns a Tree-sitter parser for the specified language.
    Supports both tree-sitter 0.25.x (with tree_sitter_python package)
    and older versions (with compiled grammars).
    """
    lang = None

    # This needs to be extended to handle multiple languages
    # For now, a simple mapping for common languages
    if language_name.lower() == "python":
        # Try new API first (tree-sitter 0.25.x with tree_sitter_python package)
        if HAS_TS_PYTHON_PACKAGE:
            try:
                lang = Language(tree_sitter_python.language())
                print(f"Loaded Python grammar from tree_sitter_python package (tree-sitter 0.25.x)")
            except Exception as e:
                print(f"Warning: Could not load from tree_sitter_python package: {e}")
                print("Falling back to compiled grammar...")
                lang = load_language_grammar("python", PYTHON_LANGUAGE_PATH)
        else:
            # Fallback to old method (compiled grammar file)
            lang = load_language_grammar("python", PYTHON_LANGUAGE_PATH)
    elif language_name.lower() == "java":
        # Support for Java using tree_sitter_java package
        if HAS_TS_JAVA_PACKAGE:
            try:
                lang = Language(tree_sitter_java.language())
                print(f"Loaded Java grammar from tree_sitter_java package")
            except Exception as e:
                print(f"Warning: Could not load from tree_sitter_java package: {e}")
                return None
        else:
            print(f"Error: tree_sitter_java package not installed. Install with: pip install tree-sitter-java")
            return None
    elif language_name.lower() == "php":
        # Support for PHP using tree_sitter_php package
        if HAS_TS_PHP_PACKAGE:
            try:
                lang = Language(tree_sitter_php.language_php())
                print(f"Loaded PHP grammar from tree_sitter_php package")
            except Exception as e:
                print(f"Warning: Could not load from tree_sitter_php package: {e}")
                return None
        else:
            print(f"Error: tree_sitter_php package not installed. Install with: pip install tree-sitter-php")
            return None
    # Add more languages here
    # elif language_name.lower() == "javascript":
    #     lang = load_language_grammar("javascript", JAVASCRIPT_LANGUAGE_PATH)
    else:
        print(f"Error: Unsupported language '{language_name}' or grammar not configured.")
        return None

    if lang:
        parser = Parser()
        # Use property assignment for newer tree-sitter versions
        # Try new API first, fallback to old API if needed
        try:
            parser.language = lang
        except AttributeError:
            # Fallback to old API for compatibility
            parser.set_language(lang)
        return parser
    return None

# Example usage (for testing purposes, not part of the main CLI flow)
if __name__ == "__main__":
    # This part would typically be handled by a build process or specific commands
    # For demonstration, assume python grammar is compiled and available
    
    # Placeholder for grammar compilation if it were possible to run shell commands
    # For a real project, you'd run:
    # git clone https://github.com/tree-sitter/tree-sitter-python grammars/python
    # tree_sitter.Language.build_library(
    #     # Store the library in the `build/grammars` directory
    #     str(PYTHON_LANGUAGE_PATH),
    #     # List of paths to the Tree-sitter grammar sources
    #     ['grammars/python']
    # )

    parser = get_parser("python")
    if parser:
        source_code = b"def factorial(n):\n    if n == 0:\n        return 1\n    else:\n        return n * factorial(n-1)"
        tree = parser.parse(source_code)
        print("Python AST parsed successfully!")
        print(tree.root_node.sexp()) # Print S-expression representation
    else:
        print("Failed to get Python parser.")

    # Example for a non-existent language
    parser = get_parser("java")
    if parser:
        print("Got Java parser (unexpected).")
