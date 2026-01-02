import tree_sitter
from tree_sitter import Language # Keep this for Language object construction
from pathlib import Path
import os
import sys

# Define paths relative to your project root
GRAMMARS_DIR = Path("grammars")
BUILD_DIR = Path("build/grammars")

# Ensure build directory exists
BUILD_DIR.mkdir(parents=True, exist_ok=True)

# Determine the correct file extension for the compiled library based on OS
if os.name == "nt":  # Windows
    LIB_EXTENSION = ".dll"
elif sys.platform == "darwin": # macOS
    LIB_EXTENSION = ".dylib"
else: # Linux and other Unix-like systems
    LIB_EXTENSION = ".so"

PYTHON_LANGUAGE_PATH = BUILD_DIR / f"python{LIB_EXTENSION}"

print(f"Building Python grammar library to: {PYTHON_LANGUAGE_PATH}")

build_successful = False
# Try the most recent (tree-sitter >= 0.21.0) way: tree_sitter.Language.build_library (standalone function)
try:
    tree_sitter.Language.build_library(
        str(PYTHON_LANGUAGE_PATH),
        [
            str(GRAMMARS_DIR / "python")
        ]
    )
    build_successful = True
except AttributeError:
    print("Fallback 1: tree_sitter.Language.build_library failed (AttributeError). Trying Language.build_library...")
except Exception as e:
    print(f"Fallback 1: tree_sitter.Language.build_library failed with unexpected error: {e}. Trying Language.build_library...")

if not build_successful:
    # Fallback for tree-sitter==0.20.x where it's a class method
    try:
        Language.build_library( # Note: this 'Language' comes from 'from tree_sitter import Language'
            str(PYTHON_LANGUAGE_PATH),
            [
                str(GRAMMARS_DIR / "python")
            ]
        )
        build_successful = True
    except AttributeError:
        print("Fallback 2: Language.build_library failed (AttributeError). Trying tree_sitter.build_library...")
    except Exception as e:
        print(f"Fallback 2: Language.build_library failed with unexpected error: {e}. Trying tree_sitter.build_library...")

if not build_successful:
    # Fallback for older tree-sitter versions where it's a standalone function `tree_sitter.build_library`
    try:
        # Import build_library if it exists as a standalone function
        from tree_sitter import build_library as old_build_library
        old_build_library(
            str(PYTHON_LANGUAGE_PATH),
            [
                str(GRAMMARS_DIR / "python")
            ]
        )
        build_successful = True
    except (ImportError, AttributeError):
        print("Fallback 3: tree_sitter.build_library failed (ImportError/AttributeError).")
    except Exception as e:
        print(f"Fallback 3: tree_sitter.build_library failed with unexpected error: {e}.")

if not build_successful:
    print("\nError: Could not find a compatible 'build_library' function for your tree-sitter version after trying all known APIs.")
    print("Please ensure your 'tree-sitter' Python package is correctly installed and compatible.")
    print(f"Your tree-sitter version appears to be {tree_sitter.__version__} (if accessible).")
    print("You might need to reinstall 'tree-sitter' or check its documentation for building grammars.")
    exit(1)

print("Python grammar library built successfully!")