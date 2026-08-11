"""
Calcul d'entropie de Shannon pour estimer le niveau d'aléa d'une chaîne.

Utilisé pour distinguer un vrai secret (haute entropie) d'une valeur
d'exemple / répétitive (basse entropie).
"""

from __future__ import annotations

import math
from collections import Counter

# Seuil calibré empiriquement (voir calibrate_entropy_threshold / smoke test) :
# - "password123", "example_key", "XXXXXXX"  → souvent < 3.5
# - JWT, clés API aléatoires                  → souvent > 4.0
# On utilise 3.5 : en dessous = aléa insuffisant pour un secret crédible.
DEFAULT_ENTROPY_THRESHOLD = 3.5


def shannon_entropy(value: str) -> float:
    """
    Entropie de Shannon en bits par caractère.

    H = -Σ p(c) * log2(p(c))

    Retourne 0.0 pour une chaîne vide.
    """
    if not value:
        return 0.0

    length = len(value)
    counts = Counter(value)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def is_low_entropy(value: str, threshold: float = DEFAULT_ENTROPY_THRESHOLD) -> bool:
    """True si l'entropie est sous le seuil (secret peu crédible)."""
    return shannon_entropy(value) < threshold


# Jeu de calibration : (label, valeur, attendu_haute_entropie)
CALIBRATION_SAMPLES: list[tuple[str, str, bool]] = [
    # Faux / exemples (basse entropie attendue)
    ("placeholder_X", "XXXXXXX", False),
    ("password123", "password123", False),
    ("example_key", "example_key", False),
    ("secret", "secret", False),
    ("aaaaaaa", "aaaaaaa", False),
    ("test_token", "test_token_value", False),
    # Vrais formats / aléatoires (haute entropie attendue)
    (
        "jwt",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        True,
    ),
    (
        "aws_key",
        "AKIAIOSFODNN7EXAMPLE",  # format AWS mais "EXAMPLE" → pattern faux ailleurs
        True,  # entropie moyenne/haute sur le format ; le pattern catchera EXAMPLE
    ),
    (
        "random_api",
        # Prefixe factice (pas sk_live_/ghp_) pour ne pas declencher GitHub Push Protection
        "rnd_key_51HqJ8kL9mN2pQrStUvWxYzAbCdEfGhIjKlMnOp",
        True,
    ),
    (
        "github_like",
        "tok_abcdefghijklmnopqrstuvwxyz0123456789ABCD",
        True,
    ),
    (
        "random_hex",
        "a3f8c91e7b2d4e6f0a1b2c3d4e5f6789abcdef0123456789",
        True,
    ),
]


def calibrate_entropy_threshold(
    samples: list[tuple[str, str, bool]] | None = None,
    candidates: list[float] | None = None,
) -> dict:
    """
    Teste plusieurs seuils sur un jeu de secrets réels vs fictifs
    et retourne le seuil qui sépare le mieux les deux classes.

    Utile pour documenter / recalibrer DEFAULT_ENTROPY_THRESHOLD.
    """
    samples = samples or CALIBRATION_SAMPLES
    candidates = candidates or [2.5, 3.0, 3.5, 4.0, 4.5]

    details = []
    for label, value, expect_high in samples:
        details.append(
            {
                "label": label,
                "entropy": shannon_entropy(value),
                "expect_high": expect_high,
                "length": len(value),
            }
        )

    best_threshold = DEFAULT_ENTROPY_THRESHOLD
    best_score = -1
    scores: list[dict] = []

    for thr in candidates:
        correct = 0
        for row in details:
            predicted_high = row["entropy"] >= thr
            if predicted_high == row["expect_high"]:
                correct += 1
        score = correct / len(details) if details else 0.0
        scores.append({"threshold": thr, "accuracy": round(score, 3)})
        if score > best_score:
            best_score = score
            best_threshold = thr

    return {
        "samples": details,
        "scores": scores,
        "best_threshold": best_threshold,
        "best_accuracy": round(best_score, 3),
        "default_used": DEFAULT_ENTROPY_THRESHOLD,
    }
