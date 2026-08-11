"""
Classification des fichiers du projet : tests vs code productif,
et détection basique du code non utilisé (jamais importé).
"""

from __future__ import annotations

import ast
from pathlib import Path

# Dossiers à ignorer lors du scan de l'arborescence
IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    ".mypy_cache",
    "dist",
    "build",
    ".tox",
}

# Patterns de noms de fichiers de test
TEST_FILE_PREFIX = "test_"
TEST_FILE_SUFFIX = "_test.py"
TEST_DIR_NAMES = {"tests", "test"}


def is_test_file(path: Path, project_root: Path) -> bool:
    """Retourne True si le chemin correspond à un fichier de test."""
    name = path.name

    if name.startswith(TEST_FILE_PREFIX) and name.endswith(".py"):
        return True
    if name.endswith(TEST_FILE_SUFFIX):
        return True

    # Fichier situé dans un dossier tests/ ou test/
    try:
        relative_parts = path.resolve().relative_to(project_root.resolve()).parts
    except ValueError:
        relative_parts = path.parts

    return any(part.lower() in TEST_DIR_NAMES for part in relative_parts[:-1])


def collect_project_files(
    project_root: str | Path,
) -> tuple[list[Path], list[Path]]:
    """
    Scanne l'arborescence du projet et retourne :
    - test_files : fichiers de test (test_*.py, *_test.py, tests/)
    - productive_files : fichiers Python productifs (hors tests)

    Les chemins sont absolus et triés pour un résultat stable.
    """
    root = Path(project_root).resolve()
    test_files: list[Path] = []
    productive_files: list[Path] = []

    for path in root.rglob("*.py"):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue

        if is_test_file(path, root):
            test_files.append(path)
        else:
            productive_files.append(path)

    return sorted(test_files), sorted(productive_files)


def _module_name_from_path(path: Path, project_root: Path) -> str | None:
    """Convertit un chemin de fichier en nom de module Python (ex: app.utils)."""
    try:
        rel = path.resolve().relative_to(project_root.resolve())
    except ValueError:
        return None

    parts = list(rel.with_suffix("").parts)
    if not parts:
        return None
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts else None


def _extract_imports(file_path: Path) -> set[str]:
    """Extrait les modules importés d'un fichier Python via ast."""
    imports: set[str] = set()
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(file_path))
    except (OSError, SyntaxError, UnicodeDecodeError):
        return imports

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
                imports.add(node.module)

    return imports


def _is_module_referenced(module: str, imported: set[str]) -> bool:
    """
    True si `module` est clairement référencé par un import.

    Exemples :
    - module=app.utils, import app.utils     → True
    - module=app.utils, import app.utils.x   → True (sous-module)
    - module=app,       import app.utils     → True (package utilisé)
    - module=app.dead,  import app.utils     → False (frère, pas le même module)
    """
    for imp in imported:
        if imp == module or imp.startswith(module + "."):
            return True
        # Import du package parent exact uniquement pour __init__ géré à part
    return False


def find_unused_files(
    project_root: str | Path,
    productive_files: list[Path] | None = None,
) -> list[Path]:
    """
    Détecte les fichiers productifs clairement non utilisés :
    aucun autre fichier productif ne les importe (analyse basique des imports).

    Les points d'entrée courants (app.py, main.py, __main__.py, wsgi.py, manage.py)
    ne sont jamais considérés comme inutilisés.
    """
    root = Path(project_root).resolve()
    if productive_files is None:
        _, productive_files = collect_project_files(root)

    entrypoints = {"app.py", "main.py", "__main__.py", "wsgi.py", "manage.py", "run.py"}

    # Ensemble de tous les modules importés depuis le code productif
    imported: set[str] = set()
    for path in productive_files:
        imported |= _extract_imports(path)

    unused: list[Path] = []
    for path in productive_files:
        if path.name in entrypoints:
            continue

        module = _module_name_from_path(path, root)
        if not module:
            continue

        # Package __init__.py : utilisé si le package ou un sous-module est importé
        if path.name == "__init__.py":
            if _is_module_referenced(module, imported):
                continue
            unused.append(path)
            continue

        # Module concret : doit être importé explicitement (pas juste un frère du package)
        if _is_module_referenced(module, imported):
            continue

        unused.append(path)

    return sorted(unused)
