import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

# Import the functions to test
from app.core.treesitter import load_language_grammar, get_parser, PYTHON_LANGUAGE_PATH

# Mock tree_sitter module
# This ensures we don't try to load actual shared libraries during tests
@pytest.fixture
def mock_tree_sitter():
    with patch('app.core.treesitter.Language') as MockLanguage, \
         patch('app.core.treesitter.Parser') as MockParser: # Patch at import location
        # Configure MockLanguage to return a mock Language object
        mock_lang_instance = MagicMock()
        MockLanguage.return_value = mock_lang_instance
        # Configure MockParser to return a mock Parser object
        mock_parser_instance = MagicMock()
        MockParser.return_value = mock_parser_instance
        yield MockLanguage, MockParser

# --- Tests for load_language_grammar ---
def test_load_language_grammar_success(mock_tree_sitter):
    MockLanguage, _ = mock_tree_sitter
    
    # Mock Path.is_file() to return True
    with patch.object(Path, 'is_file', return_value=True):
        lang = load_language_grammar("python", PYTHON_LANGUAGE_PATH)
        assert lang is not None
        MockLanguage.assert_called_once_with(str(PYTHON_LANGUAGE_PATH), "python")

def test_load_language_grammar_file_not_found():
    # Mock Path.is_file() to return False
    with patch.object(Path, 'is_file', return_value=False):
        lang = load_language_grammar("python", Path("non_existent.so"))
        assert lang is None # Expect None if file not found

def test_load_language_grammar_exception(mock_tree_sitter):
    MockLanguage, _ = mock_tree_sitter
    # Configure MockLanguage constructor to raise an exception
    MockLanguage.side_effect = Exception("Failed to load grammar")

    with patch.object(Path, 'is_file', return_value=True):
        lang = load_language_grammar("python", PYTHON_LANGUAGE_PATH)
        assert lang is None # Expect None if loading fails

# --- Tests for get_parser ---
def test_get_parser_supported_language_success(mock_tree_sitter):
    MockLanguage, MockParser = mock_tree_sitter

    # Ensure load_language_grammar succeeds
    mock_lang = MagicMock()
    with patch('app.core.treesitter.load_language_grammar', return_value=mock_lang):
        parser = get_parser("python")
        assert parser is not None
        MockParser.assert_called_once() # Parser should be instantiated
        # Check that language was set (either via property or method)
        # The new API uses property assignment: parser.language = lang
        assert parser.language == mock_lang or (hasattr(parser, 'set_language') and parser.set_language.called)

def test_get_parser_unsupported_language():
    parser = get_parser("unsupported")
    assert parser is None

def test_get_parser_grammar_loading_fails():
    # Mock load_language_grammar to return None
    with patch('app.core.treesitter.load_language_grammar', return_value=None):
        parser = get_parser("python")
        assert parser is None
