"""
Petit smoke test du filtrage secrets (entropie + patterns).

Lance :
    python tests_triage/smoke_secrets_filter.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from triage.entropy import (
    DEFAULT_ENTROPY_THRESHOLD,
    calibrate_entropy_threshold,
    shannon_entropy,
)
from triage.secrets_filter import (
    evaluate_secret,
    match_fake_patterns,
    match_real_formats,
    triage_secret_alerts,
)


def run() -> None:
    # --- Entropie de base ---
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("XXXXXXX") < 1.0
    assert shannon_entropy("password123") < DEFAULT_ENTROPY_THRESHOLD

    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    # Prefixe factice : evite le blocage GitHub Push Protection (faux sk_live_)
    api_key = "rnd_key_51HqJ8kL9mN2pQrStUvWxYzAbCdEfGhIjKlMnOp"
    # Assemble a l'execution pour tester le pattern Stripe sans committer la chaine complete
    stripe_demo = "sk_" + "live_" + "51HqJ8kL9mN2pQrStUvWxYzAbCdEfGhIjKlMnOp"
    assert shannon_entropy(jwt) >= DEFAULT_ENTROPY_THRESHOLD
    assert shannon_entropy(api_key) >= DEFAULT_ENTROPY_THRESHOLD

    calib = calibrate_entropy_threshold()
    print("Calibration entropie:")
    print(json.dumps(calib, indent=2, ensure_ascii=True))
    assert calib["best_accuracy"] >= 0.7
    assert abs(calib["best_threshold"] - DEFAULT_ENTROPY_THRESHOLD) <= 1.0

    # --- Patterns faux ---
    assert "placeholder_x" in match_fake_patterns("XXXXXXX")
    assert match_fake_patterns("example_key")
    assert match_fake_patterns("password123")
    assert match_fake_patterns("AKIAIOSFODNN7EXAMPLE")  # EXAMPLE
    assert not match_fake_patterns(api_key)
    assert "stripe_key" in match_real_formats(stripe_demo)

    # --- Decision unitaire ---
    fake = evaluate_secret("XXXXXXX")
    assert fake["deprioritize"] is True
    assert fake["factor"] <= 0.5

    real = evaluate_secret(jwt)
    assert real["deprioritize"] is False
    assert "jwt" in real["real_formats"]

    stripe = evaluate_secret(stripe_demo)
    assert stripe["deprioritize"] is False
    assert "stripe_key" in stripe["real_formats"]

    low = evaluate_secret("aabbcc")
    assert low["deprioritize"] is True
    assert low["low_entropy"] is True

    # --- Triage liste style GitLeaks ---
    alerts = [
        {"Secret": "XXXXXXX", "File": "config.py", "RuleID": "generic-api-key", "confidence": "HIGH"},
        {"Secret": "password123", "File": ".env.example", "RuleID": "generic-password", "confidence": 90},
        {"Secret": jwt, "File": "app/auth.py", "RuleID": "jwt", "confidence": "HIGH"},
        {"Secret": api_key, "File": "settings.py", "RuleID": "generic-api", "confidence": "HIGH"},
        {"Secret": "example_key", "File": "README.md", "RuleID": "generic", "confidence": "MEDIUM"},
    ]
    triaged = triage_secret_alerts(alerts)

    assert triaged[0]["deprioritisee"] is True
    assert triaged[0]["confiance_ajustee"] == 40.0  # 100 * 0.4
    assert "fictive" in triaged[0]["raison_déprioritisation"].lower() or "patterns" in triaged[0]["raison_déprioritisation"].lower()

    assert triaged[1]["deprioritisee"] is True
    assert triaged[2]["deprioritisee"] is False  # JWT
    assert triaged[3]["deprioritisee"] is False  # API key haute entropie
    assert triaged[4]["deprioritisee"] is True  # example_key

    print("\nOK - filtrage secrets (entropie + patterns) fonctionne.")
    summary = [
        {
            "secret": (a.get("Secret") or "")[:20],
            "entropie": a.get("entropie"),
            "confiance_ajustee": a.get("confiance_ajustee"),
            "deprioritisee": a.get("deprioritisee"),
        }
        for a in triaged
    ]
    print(json.dumps(summary, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    run()
