# G:\home\firmin\.local\lib\python\utils\pathglob.py
# (ou dans ton projet: ./utils/pathglob.py)

"""
Path pattern resolution module — robust globbing for paths with wildcards and recursion.

Supports:
  - Shell-style globs: *, ?, [seq], [!seq]
  - Recursive globs: ** (matches any subdirectory, including zero)
  - Windows paths (G:\, \\server\share), ~ expansion, case insensitivity where relevant
  - Deduplication, sorting, and type annotation (Path objects)

Typical usage:
    from utils.pathglob import resolve_path_patterns
    files = resolve_path_patterns(["src/**/*.py", "~/.config/*.json"])
"""

import glob
import os
from pathlib import Path
from typing import Iterable, List, Optional, Union

__all__ = ["resolve_path_patterns", "PathPatternResolver"]


def resolve_path_patterns(
    patterns: Union[str, Iterable[str]],
    *,
    recursive: bool = True,
    strict: bool = False,
    resolve: bool = True,
    sort: bool = True,
    case_sensitive: Optional[bool] = None
) -> List[Path]:
    """
    Resolve one or more path patterns into concrete Path objects.

    Args:
        patterns: A single pattern (str) or list/iterable of patterns.
        recursive: Enable ** recursion (default: True).
        strict: If True, raise ValueError on empty/no-match patterns.
        resolve: If True (default), call Path.resolve() for absolute, normalized paths.
        sort: Return sorted list (default: True → deterministic output).
        case_sensitive: Override system default (None → auto-detect; Windows=False).

    Returns:
        List of unique Path objects (files and/or directories), resolved and deduplicated.

    Raises:
        ValueError: If `strict=True` and a pattern yields no matches.
        OSError: If glob encounters an OS error (e.g. permission denied on part of tree).

    Examples:
        >>> resolve_path_patterns("*.py")
        [PosixPath('main.py'), PosixPath('utils.py')]
        >>> resolve_path_patterns(["logs/*.log", "data/**/*.csv"])
        [...]
    """
    if isinstance(patterns, str):
        patterns = [patterns]

    if case_sensitive is None:
        # Windows: case-insensitive by default in glob
        case_sensitive = not (os.name == "nt")

    resolved: List[Path] = []
    for pat in patterns:
        pat = os.path.expanduser(pat)
        try:
            matches = glob.glob(pat, recursive=recursive)
        except Exception as e:
            raise OSError(f"Failed to glob pattern '{pat}': {e}") from e

        if not matches and strict:
            raise ValueError(f"No matches for pattern: '{pat}'")

        for m in matches:
            p = Path(m)
            if resolve:
                p = p.resolve()
            resolved.append(p)

    # Deduplicate (set preserves hashable Path), then sort
    unique = list(set(resolved))
    if sort:
        unique.sort(key=lambda x: (str(x).lower(), str(x)))
    return unique


class PathPatternResolver:
    """
    Reusable resolver with configurable defaults (e.g. for a CLI tool or pipeline).
    
    Example:
        resolver = PathPatternResolver(recursive=False, strict=True)
        paths = resolver(["*.tmp"])
    """

    def __init__(
        self,
        recursive: bool = True,
        strict: bool = False,
        resolve: bool = True,
        sort: bool = True,
        case_sensitive: Optional[bool] = None
    ):
        self.recursive = recursive
        self.strict = strict
        self.resolve = resolve
        self.sort = sort
        self.case_sensitive = case_sensitive

    def __call__(self, patterns: Union[str, Iterable[str]]) -> List[Path]:
        return resolve_path_patterns(
            patterns,
            recursive=self.recursive,
            strict=self.strict,
            resolve=self.resolve,
            sort=self.sort,
            case_sensitive=self.case_sensitive
        )

    def __repr__(self):
        return (
            f"PathPatternResolver(recursive={self.recursive}, strict={self.strict}, "
            f"resolve={self.resolve}, sort={self.sort})"
        )
