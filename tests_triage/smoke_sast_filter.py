"""
Petit smoke test du filtrage SAST (sans pytest requis).

Lance :
    python tests_triage/smoke_sast_filter.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

# Racine du repo
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from triage.file_scanner import collect_project_files, find_unused_files
from triage.sast_filter import triage_sast_alerts


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def run() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        # Code productif
        _write(root / "app" / "main.py", "from app.utils import helper\nhelper()\n")
        _write(root / "app" / "utils.py", "def helper():\n    return 1\n")
        _write(root / "app" / "__init__.py", "")
        # Code mort (jamais importé)
        _write(root / "app" / "dead_code.py", "PASSWORD = 'secret'\n")

        # Fichiers de test (3 patterns)
        _write(root / "tests" / "test_main.py", "def test_ok():\n    assert True\n")
        _write(root / "app" / "test_utils.py", "def test_u():\n    assert True\n")
        _write(root / "app" / "utils_test.py", "def test_v():\n    assert True\n")

        test_files, productive = collect_project_files(root)
        test_names = {p.name for p in test_files}
        prod_names = {p.name for p in productive}

        assert "test_main.py" in test_names, test_names
        assert "test_utils.py" in test_names, test_names
        assert "utils_test.py" in test_names, test_names
        assert "main.py" in prod_names
        assert "utils.py" in prod_names
        assert "dead_code.py" in prod_names
        assert "test_main.py" not in prod_names

        unused = find_unused_files(root, productive)
        unused_names = {p.name for p in unused}
        assert "dead_code.py" in unused_names, unused_names
        assert "utils.py" not in unused_names  # importé par main
        assert "main.py" not in unused_names  # point d'entrée

        alerts = [
            {
                "filename": str(root / "tests" / "test_main.py"),
                "issue_confidence": "HIGH",
                "issue_text": "assert utilisé",
                "test_id": "B101",
            },
            {
                "filename": str(root / "app" / "dead_code.py"),
                "issue_confidence": "HIGH",
                "issue_text": "hardcoded password",
                "test_id": "B105",
            },
            {
                "filename": str(root / "app" / "utils.py"),
                "issue_confidence": "MEDIUM",
                "issue_text": "something",
                "test_id": "B110",
            },
        ]

        triaged = triage_sast_alerts(alerts, root)

        # Test file → confiance / 2
        assert triaged[0]["deprioritisee"] is True
        assert triaged[0]["confiance_ajustee"] == 50.0
        assert "fichier de test" in triaged[0]["raison_déprioritisation"].lower()

        # Unused → confiance / 2
        assert triaged[1]["deprioritisee"] is True
        assert triaged[1]["confiance_ajustee"] == 50.0
        assert "non importé" in triaged[1]["raison_déprioritisation"].lower()

        # Productive used → inchangé
        assert triaged[2]["deprioritisee"] is False
        assert triaged[2]["confiance_ajustee"] == 70.0

        print("OK - filtrage SAST (tests + code non utilise) fonctionne.")
        summary = [
            {
                "file": Path(a["filename"]).name,
                "confiance_ajustee": a["confiance_ajustee"],
                "deprioritisee": a["deprioritisee"],
                "raison": a["raison_déprioritisation"],
            }
            for a in triaged
        ]
        print(json.dumps(summary, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    run()
