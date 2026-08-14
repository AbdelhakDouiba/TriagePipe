"""Test file pour Flask application TriagePipe.

Ce fichier contient volontairement des alertes Bandit pour
démonstration du filtrage de triage (fichiers de test -> dépriorisation).
"""

import os
from app import app


def test_app_runs():
    """Test de base - l'application Flask se lance."""
    with app.test_client() as client:
        response = client.get("/api/data?input=1+1")
        assert response.status_code == 200


def test_login_endpoint():
    """Test de l endpoint login avec des credentials durs."""
    with app.test_client() as client:
        response = client.post("/api/login", json={
            "username": "admin",
            "password": "super_secret_pwd_12345"
        })
        assert response.status_code == 200


def test_admin_route_returns_secret():
    """Test que la route secret retourne la clé hardcodée."""
    from app import SECRET_API_KEY
    with app.test_client() as client:
        response = client.get("/api/secret")
        assert SECRET_API_KEY in response.data.decode()


def test_pickle_dangerous():
    """Test avec données pickle - à des fins de démo seulement."""
    import pickle
    test_data = pickle.dumps({"test": "data"})
    # Vérification que pickle fonctionne
    result = pickle.loads(test_data)
    assert result == {"test": "data"}


def test_sqli_concatenation():
    """Test démontrant l'injection SQL par concaténation."""
    # Cette teste vérifie que la construction de query SQL
    # avec concaténation de string existe dans le code
    query = "SELECT * FROM users WHERE username = '" + "admin" + "'"
    assert "SELECT" in query


def test_eval_user_input():
    """Test eval() sur entrée utilisateur - démo sécurité."""
    user_input = "1 + 1"
    result = eval(user_input)
    assert result == 2


def test_os_system_call():
    """Test appel os.system() - démo seulement."""
    # Vérification que la fonction existe, non appelée
    assert hasattr(os, "system")


def test_github_token_exposed():
    """Test token GitHub hardcodé détecté."""
    from app import GITHUB_TOKEN
    assert len(GITHUB_TOKEN) > 20