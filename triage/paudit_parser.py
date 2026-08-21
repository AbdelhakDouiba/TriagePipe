"""Parseur normalisateur de résultats pip-audit (SCA).

Lit la sortie JSON de pip-audit et mappe les champs vers un schéma uniforme :
- id_alerte: identifiant de la vulnérabilité (CVE ou PYSEC)
- fichier: nom du package en cause
- ligne: version vulnérable (non utilisé pour SCA, mis sous forme de texte)
- sévérité_brute: sévérité de la CVE
- description: description du vulnérabilité
- outil: outil source ('pip-audit')
"""

from __future__ import annotations

from typing import Any, List, Dict
import json
from pathlib import Path


def normalize_paudit_result(result: dict[str, Any]) -> dict[str, str]:
    """Normalise une vulnérabilité pip-audit vers le schéma uniforme.

    Mapping des champs :
    - pkg.name        → fichier
    - pkg.version     → ligne (version installée)
    - vuln.id         → id_alerte (CVE ou PYSEC)
    - vuln.fix_versions → version corrigée (première valeur)
    - vuln.description → description
    → outil (fixe à 'pip-audit')

    Args:
        result: Dictionnaire représentant une vulnérabilité issue du rapport
                pip-audit (un élément du tableau 'dependencies[][].vulns[]'.

    Returns:
        Dictionnaire normalisé avec les clés standardisées.
    """
    pkg = result.get("pkg", {})
    vuln = result.get("vuln", {})

    # Extraction de l'identifiant (CVE ou PYSEC)
    vuln_id = vuln.get("id", "")
    # On enlève le préfixe "PYSEC-" pour avoir le numéro seulement, ou on garde tel quel
    if vuln_id.startswith("PYSEC-"):
        vuln_id_numeric = vuln_id.split("-")[1]
    else:
        vuln_id_numeric = vuln_id

    # Version corrigée : prendre la première valeur disponible
    fix_versions = vuln.get("fix_versions", [])
    version_corrigée = fix_versions[0] if fix_versions else ""

    return {
        "id_alerte": vuln_id,
        "fichier": pkg.get("name", ""),
        "ligne": pkg.get("version", ""),
        "séverté_brute": "",  # pip-audit ne fournit pas de sévérité classique LOW/MEDIUM/HIGH dans ce format
        "description": vuln.get("description", ""),
        "outil": "pip-audit",
    }


def parse_paudit_report(report_path: str | Path) -> List[dict[str, str]]:
    """Parse un rapport pip-audit complet et retourne les vulnérabilités normalisées.

    Lit le fichier JSON généré par `pip-audit -r requirements.txt -f json -o results.json`,
    parcourt le tableau 'dependencies' et normalise chaque vulnérabilité via
    normalize_paudit_result().

    Args:
        report_path: Chemin vers le fichier JSON de résultats pip-audit.

    Returns:
        Liste de dictionnaires, chaque dictionnaire représentant une vulnérabilité
        au format normalisé (id_alerte, fichier, ligne, sévérité_brute,
        description, outil).
    """
    data = Path(report_path).read_text(encoding="utf-8")
    parsed = json.loads(data)

    vulnerabilities: list[dict[str, str]] = []

    for dep in parsed.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            normalized = normalize_paudit_result({"pkg": dep, "vuln": vuln})
            vulnerabilities.append(normalized)

    return vulnerabilities


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m triage_paudit <chemin_rapport_pip_audit>")
        sys.exit(1)

    report_path = sys.argv[1]
    vulnerabilities = parse_paudit_report(report_path)

    print(f"\n=== pip-audit Report Summary ===")
    print(f"Total vulnérabilités trouvées: {len(vulnerabilities)}")
    print(f"\nVulnérabilités normalisées :")

    for vuln in vulnerabilities:
        print(f"\n  - id_alerte:     {vuln['id_alerte']}")
        print(f"    fichier:       {vuln['fichier']}")
        print(f"    version installée: {vuln['ligne']}")
        print(f"    version corrigée: {vuln.get('version_corrigée', 'N/A')}")
        print(f"    sévérité_brute: {vuln['séverté_brute']}")
        print(f"    description:   {vuln['description'][:80]}...")
        print(f"    outil:         {vuln['outil']}")