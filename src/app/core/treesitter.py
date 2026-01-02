import os # New import
from pathlib import Path
from typing import Optional

from tree_sitter import Language, Parser

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
    Assumes pre-compiled grammars are available.
    """
    # This needs to be extended to handle multiple languages
    # For now, a simple mapping for common languages
    if language_name.lower() == "python":
        lang = load_language_grammar("python", PYTHON_LANGUAGE_PATH)
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
