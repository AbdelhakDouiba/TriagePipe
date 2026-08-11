"""
Filtrage des secrets (GitLeaks) : entropie + patterns de faux positifs.

Réduit la confiance des alertes dont la valeur ressemble à un exemple,
un placeholder ou une chaîne trop peu aléatoire pour être un vrai secret.
"""

from __future__ import annotations

import re
from typing import Any

from .entropy import DEFAULT_ENTROPY_THRESHOLD, is_low_entropy, shannon_entropy

# Confiance GitLeaks souvent absente → score par défaut
DEFAULT_CONFIDENCE = 80.0

# Réduction si faux positif probable
FAKE_SECRET_FACTOR = 0.4  # -60 %
LOW_ENTROPY_FACTOR = 0.5  # -50 %

# ---------------------------------------------------------------------------
# Patterns de FAUX secrets (placeholders, exemples, valeurs statiques)
# ---------------------------------------------------------------------------
FAKE_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "placeholder_x": re.compile(r"^X{4,}$", re.IGNORECASE),
    "placeholder_stars": re.compile(r"^\*{4,}$"),
    "placeholder_dots": re.compile(r"^\.{4,}$"),
    "placeholder_your": re.compile(
        r"(your[_-]?api[_-]?key|your[_-]?token|your[_-]?secret|"
        r"insert[_-]?.+|replace[_-]?.+|<.*>|\{.*\})",
        re.IGNORECASE,
    ),
    "example_keyword": re.compile(
        r"(example|sample|dummy|fake|placeholder|changeme|todo|fixme)",
        re.IGNORECASE,
    ),
    "example_key_name": re.compile(
        r"^(example[_-]?key|test[_-]?key|demo[_-]?key|sample[_-]?token|"
        r"test[_-]?secret|dummy[_-]?secret|fake[_-]?token)$",
        re.IGNORECASE,
    ),
    "common_passwords": re.compile(
        r"^(password|password123|passw0rd|admin|admin123|root|secret|"
        r"secret123|qwerty|123456|12345678|letmein|welcome)$",
        re.IGNORECASE,
    ),
    "aws_example": re.compile(r"EXAMPLE", re.IGNORECASE),
    "redacted": re.compile(r"(redacted|removed|censored|xxx+)", re.IGNORECASE),
    "lorem": re.compile(r"lorem|ipsum", re.IGNORECASE),
    "foo_bar": re.compile(r"^(foo|bar|baz|qux)([_-]?(foo|bar|baz|qux))?$", re.IGNORECASE),
}

# ---------------------------------------------------------------------------
# Formats de VRAIS secrets (renforce la crédibilité si match + haute entropie)
# ---------------------------------------------------------------------------
REAL_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "jwt": re.compile(
        r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"
    ),
    "aws_access_key": re.compile(r"^AKIA[0-9A-Z]{16}$"),
    "github_pat": re.compile(r"^gh[pousr]_[A-Za-z0-9_]{20,}$"),
    "github_fine_grained": re.compile(r"^github_pat_[A-Za-z0-9_]{20,}$"),
    "slack_token": re.compile(r"^xox[baprs]-[A-Za-z0-9-]{10,}$"),
    "stripe_key": re.compile(r"^sk_(live|test)_[A-Za-z0-9]{20,}$"),
    "google_api": re.compile(r"^AIza[0-9A-Za-z_-]{35}$"),
    "private_key_header": re.compile(
        r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"
    ),
}


def match_fake_patterns(secret: str) -> list[str]:
    """Retourne la liste des noms de patterns faux qui matchent."""
    hits: list[str] = []
    for name, pattern in FAKE_SECRET_PATTERNS.items():
        if pattern.search(secret):
            hits.append(name)
    return hits


def match_real_formats(secret: str) -> list[str]:
    """Retourne la liste des formats de vrais secrets qui matchent."""
    hits: list[str] = []
    for name, pattern in REAL_SECRET_PATTERNS.items():
        if pattern.search(secret):
            hits.append(name)
    return hits


def _extract_secret_value(alert: dict[str, Any]) -> str:
    """Récupère la valeur du secret depuis un finding GitLeaks (champs usuels)."""
    for key in ("Secret", "secret", "Match", "match", "Offender", "string"):
        value = alert.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _to_confidence(raw: Any) -> float:
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str):
        mapping = {"HIGH": 100.0, "MEDIUM": 70.0, "LOW": 40.0}
        return mapping.get(raw.upper(), DEFAULT_CONFIDENCE)
    return DEFAULT_CONFIDENCE


def evaluate_secret(
    secret: str,
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
) -> dict[str, Any]:
    """
    Analyse une chaîne secrète : entropie, patterns faux, formats réels.

    Retourne un dict de décision (sans muter d'alerte).
    """
    entropy = shannon_entropy(secret)
    fake_hits = match_fake_patterns(secret)
    real_hits = match_real_formats(secret)
    low_ent = is_low_entropy(secret, entropy_threshold)

    reasons: list[str] = []
    factor = 1.0
    deprioritize = False

    # 1) Patterns de faux secrets → forte réduction
    if fake_hits:
        deprioritize = True
        factor = min(factor, FAKE_SECRET_FACTOR)
        reasons.append(
            f"Valeur fictive/exemple detectee (patterns: {', '.join(fake_hits)})."
        )

    # 2) Format réel reconnu → on conserve (sauf si clairement un exemple)
    if real_hits and not fake_hits:
        reasons.append(
            f"Format de secret reconnu ({', '.join(real_hits)}) : confiance conservee."
        )
    elif real_hits and fake_hits:
        reasons.append(
            f"Format reconnu ({', '.join(real_hits)}) mais marqueur d'exemple present."
        )

    # 3) Basse entropie sans format réel → réduction
    if low_ent and not real_hits:
        deprioritize = True
        factor = min(factor, LOW_ENTROPY_FACTOR)
        reasons.append(
            f"Entropie faible ({entropy} < {entropy_threshold}) : "
            "alea insuffisant pour un secret credible."
        )
    elif not low_ent and not fake_hits:
        if not reasons:
            reasons.append(
                f"Entropie suffisante ({entropy} >= {entropy_threshold}) "
                "et aucun pattern fictif : confiance conservee."
            )

    if not reasons:
        reasons.append("Aucune regle de deprioritisation declenchee.")

    return {
        "secret_preview": (secret[:8] + "...") if len(secret) > 8 else secret,
        "entropy": entropy,
        "entropy_threshold": entropy_threshold,
        "fake_patterns": fake_hits,
        "real_formats": real_hits,
        "low_entropy": low_ent,
        "deprioritize": deprioritize,
        "factor": factor,
        "reasons": reasons,
    }


def triage_secret_alerts(
    alerts: list[dict[str, Any]],
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
) -> list[dict[str, Any]]:
    """
    Pour chaque alerte GitLeaks :
    - calcule l'entropie ;
    - applique les patterns de faux secrets ;
    - réduit la confiance si faux positif probable ;
    - ajoute 'raison_déprioritisation'.
    """
    triaged: list[dict[str, Any]] = []

    for alert in alerts:
        result = dict(alert)
        secret = _extract_secret_value(alert)
        original = _to_confidence(
            alert.get("issue_confidence") or alert.get("confidence")
        )
        result["confiance_originale"] = original

        if not secret:
            result["confiance_ajustee"] = original
            result["deprioritisee"] = False
            result["raison_déprioritisation"] = (
                "Impossible d'extraire la valeur du secret ; confiance inchangee."
            )
            result["entropie"] = None
            triaged.append(result)
            continue

        decision = evaluate_secret(secret, entropy_threshold)
        result["entropie"] = decision["entropy"]
        result["fake_patterns"] = decision["fake_patterns"]
        result["real_formats"] = decision["real_formats"]

        if decision["deprioritize"]:
            adjusted = round(original * decision["factor"], 1)
            result["confiance_ajustee"] = adjusted
            result["deprioritisee"] = True
            result["raison_déprioritisation"] = (
                " ".join(decision["reasons"])
                + f" Confiance reduite ({original} -> {adjusted})."
            )
            result["issue_confidence"] = adjusted
        else:
            result["confiance_ajustee"] = original
            result["deprioritisee"] = False
            result["raison_déprioritisation"] = " ".join(decision["reasons"])

        triaged.append(result)

    return triaged


def triage_gitleaks_report(
    gitleaks_json: list[dict[str, Any]] | dict[str, Any],
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
) -> dict[str, Any]:
    """
    Applique le triage sur un export GitLeaks (liste de findings ou dict wrappé).
    """
    if isinstance(gitleaks_json, list):
        raw = gitleaks_json
        wrapper: dict[str, Any] = {"findings": raw}
    else:
        wrapper = dict(gitleaks_json)
        raw = list(
            gitleaks_json.get("findings")
            or gitleaks_json.get("results")
            or gitleaks_json.get("leaks")
            or []
        )

    triaged = triage_secret_alerts(raw, entropy_threshold)
    wrapper["findings"] = triaged
    wrapper["triage"] = {
        "total_brut": len(raw),
        "deprioritisees": sum(1 for a in triaged if a.get("deprioritisee")),
        "retenues_pleine_confiance": sum(
            1 for a in triaged if not a.get("deprioritisee")
        ),
        "entropy_threshold": entropy_threshold,
    }
    return wrapper
