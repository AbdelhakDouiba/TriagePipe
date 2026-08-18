"""Parseur normalisateur de résultats Bandit (SAST).

Lit la sortie JSON de Bandit et mappe les champs vers un schéma uniforme :
- id_alerte: identifiant de l'alerte (test_id Bandit)
- fichier: chemin du fichier analysé
- ligne: numéro de ligne en cause
- sévérité_brute: niveau de sévérité original (LOW/MEDIUM/HIGH)
- description: description du findings
- outil: outil source ('bandit')
"""

from __future__ import annotations

from typing import Any, List, Dict
from pathlib import Path


def normalize_bandit_result(result: dict[str, Any]) -> dict[str, str]:
    """Normalise une alerte Bandit vers le schéma uniforme.

    Mapping des champs :
    - test_id       → id_alerte
    - filename      → fichier
    - line_number   → ligne
    - issue_severity → sévérité_brute
    - issue_text    → description
    - → outil (fixe à 'bandit')

    Args:
        result: Dictionnaire représentant une alerte issue du rapport JSON
                Bandit (un élément du tableau 'results').

    Returns:
        Dictionnaire normalisé avec les clés standardisées.
    """
    return {
        "id_alerte": result.get("test_id", ""),
        "fichier": result.get("filename", ""),
        "ligne": str(result.get("line_number", "")),
        "séverté_brute": result.get("issue_severity", ""),
        "description": result.get("issue_text", ""),
        "outil": "bandit",
    }


def parse_bandit_report(report_path: str | Path) -> List[dict[str, str]]:
    """Parse un rapport Bandit complet et retourne les alertes normalisées.

    Lit le fichier JSON généré par `bandit -r . -f json -o results.json`,
    extrait le tableau 'results' et normalise chaque alerte via
    normalize_bandit_result().

    Args:
        report_path: Chemin vers le fichier JSON de résultats Bandit.

    Returns:
        Liste de dictionnaires, chaque dictionnaire représentant une alerte
        au format normalisé (id_alerte, fichier, ligne, sévérité_brute,
        description, outil).
    """
    data = Path(report_path).read_text(encoding="utf-8")
    import json
    parsed = json.loads(data)

    results_raw = parsed.get("results", [])
    normalized: list[dict[str, str]] = []

    for alert in results_raw:
        normalized.append(normalize_bandit_result(alert))

    return normalized


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m triage_bandit_parser <chemin_rapport_bandit>")
        sys.exit(1)

    report_path = sys.argv[1]
    alerts = parse_bandit_report(report_path)

    print(f"\n=== Bandit Report Summary ===")
    print(f"Total alerts found: {len(alerts)}")
    print(f"\nNormalized alerts:")

    for alert in alerts:
        print(f"\n  - id_alerte:     {alert['id_alerte']}")
        print(f"    fichier:       {alert['fichier']}")
        print(f"    ligne:         {alert['ligne']}")
        print(f"    sévérité_brute: {alert['séverté_brute']}")
        print(f"    description:   {alert['description'][:80]}...")
        print(f"    outil:         {alert['outil']}")