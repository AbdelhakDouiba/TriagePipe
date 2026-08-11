"""
Filtrage SAST : dépriorisation des alertes dans les fichiers de test
et dans le code clairement non utilisé.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .file_scanner import collect_project_files, find_unused_files

# Correspondance confiance Bandit (texte) -> score numérique 0–100
CONFIDENCE_MAP = {
    "HIGH": 100,
    "MEDIUM": 70,
    "LOW": 40,
}

# Facteur de réduction lorsque l'alerte est dans un fichier de test / inutilisé
DEPRIORITIZE_FACTOR = 0.5


def _normalize_path(path_str: str, project_root: Path) -> Path:
    """Normalise un chemin d'alerte (relatif ou absolu) vers un Path résolu."""
    p = Path(path_str)
    if not p.is_absolute():
        p = project_root / p
    try:
        return p.resolve()
    except OSError:
        return p


def _to_confidence_score(raw: Any) -> float:
    """Convertit une confiance Bandit (str ou nombre) en score 0–100."""
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str):
        return float(CONFIDENCE_MAP.get(raw.upper(), 70))
    return 70.0


def triage_sast_alerts(
    alerts: list[dict[str, Any]],
    project_root: str | Path,
) -> list[dict[str, Any]]:
    """
    Pour chaque alerte SAST :
    - vérifie si le fichier est un fichier de test (liste noire) ;
    - vérifie si le fichier est du code productif non utilisé ;
    - réduit la confiance de 50 % si l'un des cas est détecté ;
    - ajoute le champ 'raison_déprioritisation' expliquant la décision.

    Les fichiers productifs forment la liste blanche : une alerte y située
    (et utilisée) conserve sa confiance d'origine.
    """
    root = Path(project_root).resolve()
    test_files, productive_files = collect_project_files(root)

    # Listes blanche / noire (chemins résolus)
    test_set = {p.resolve() for p in test_files}
    productive_set = {p.resolve() for p in productive_files}
    unused_set = {p.resolve() for p in find_unused_files(root, productive_files)}

    triaged: list[dict[str, Any]] = []

    for alert in alerts:
        # Copie pour ne pas muter l'entrée d'origine
        result = dict(alert)

        filename = alert.get("filename") or alert.get("file") or alert.get("path") or ""
        file_path = _normalize_path(str(filename), root) if filename else None

        original_confidence = _to_confidence_score(
            alert.get("issue_confidence") or alert.get("confidence") or "MEDIUM"
        )
        result["confiance_originale"] = original_confidence
        reasons: list[str] = []

        if file_path is None or not filename:
            result["confiance_ajustee"] = original_confidence
            result["raison_déprioritisation"] = (
                "Impossible de déterminer le fichier source de l'alerte."
            )
            result["deprioritisee"] = False
            triaged.append(result)
            continue

        # --- Liste noire : fichiers de test ---
        if file_path in test_set:
            reasons.append(
                f"Alerte située dans un fichier de test ({file_path.name}) : "
                "les findings dans les tests sont généralement moins prioritaires."
            )

        # --- Code productif clairement non utilisé ---
        elif file_path in unused_set:
            reasons.append(
                f"Fichier productif non importé ailleurs dans le projet "
                f"({file_path.name}) : code probablement mort / non atteint."
            )

        # --- Liste blanche : code productif utilisé ---
        elif file_path in productive_set:
            # Pas de dépriorisation
            pass
        else:
            # Fichier hors scan (ex: généré, hors racine) — on ne touche pas
            reasons.append(
                "Fichier hors de l'arborescence scannée ; confiance inchangée."
            )
            result["confiance_ajustee"] = original_confidence
            result["raison_déprioritisation"] = reasons[0]
            result["deprioritisee"] = False
            triaged.append(result)
            continue

        if reasons:
            adjusted = round(original_confidence * DEPRIORITIZE_FACTOR, 1)
            result["confiance_ajustee"] = adjusted
            result["raison_déprioritisation"] = " ".join(reasons) + (
                f" Confiance reduite de 50% ({original_confidence} -> {adjusted})."
            )
            result["deprioritisee"] = True
            # Champ pratique pour le pipeline (optionnel)
            result["issue_confidence"] = adjusted
        else:
            result["confiance_ajustee"] = original_confidence
            result["raison_déprioritisation"] = (
                "Fichier productif utilisé : aucune dépriorisation."
            )
            result["deprioritisee"] = False

        triaged.append(result)

    return triaged


def triage_bandit_report(
    bandit_json: dict[str, Any],
    project_root: str | Path,
) -> dict[str, Any]:
    """
    Applique le triage sur un rapport Bandit complet (clé 'results').
    Retourne une copie du rapport avec les alertes enrichies.
    """
    report = dict(bandit_json)
    raw_results = list(bandit_json.get("results") or [])
    report["results"] = triage_sast_alerts(raw_results, project_root)
    report["triage"] = {
        "total_brut": len(raw_results),
        "deprioritisees": sum(
            1 for a in report["results"] if a.get("deprioritisee")
        ),
        "retenues_pleine_confiance": sum(
            1 for a in report["results"] if not a.get("deprioritisee")
        ),
    }
    return report
