"""Flask application avec vulnérabilités SAST intentionnelles.

Ce fichier sert d'exemple de démo pour TriagePipe.
Il contient deliberately des failles de sécurité courantes
pour démonstration du pipeline de triage.
"""

import pickle
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# Clé API hardcodée - détectable par Bandit B105 / B101
SECRET_API_KEY = "sk-live-51HqJ8kL9mN2pQrStUvWxYzAbCdEfGhIjKlMnOp"
DEBUG_MODE = True

# Mot de passe base de données hardcodée
DB_PASSWORD = "super_secret_pwd_12345"

# Configuration avec secrets fictifs
GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD"


@app.route("/api/data", methods=["GET"])
def get_data():
    """Route récupérant des données avec eval() non sécurisé."""
    user_input = request.args.get("input", "")
    # VULN: utilisation de eval() sur entrée utilisateur
    result = eval(user_input)
    return jsonify({"result": result})


@app.route("/api/login", methods=["POST"])
def login():
    """Route de connexion avec construction SQL en dur."""
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    # VULN: construction de requête SQL sans paramètres (injection SQL)
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    # En production, utiliser des parametres requetes: query = "SELECT * FROM users WHERE username = ? AND password = ?", (username, password)

    # Simuler une verification
    if username == "admin" and password == DB_PASSWORD:
        return jsonify({"status": "ok", "token": SECRET_API_KEY})
    return jsonify({"status": "fail"}), 401


@app.route("/api/predict", methods=["POST"])
def predict():
    """Route utilisant pickle.loads() non sécurisé."""
    data = request.get_json()
    # VULN: pickle.loads() sur données non confiancees
    result = pickle.loads(data.get("model_data", b""))
    return jsonify({"result": str(result)})


@app.route("/api/calc", methods=["GET"])
def calculate():
    """Route avec calcul dynamique via eval()."""
    expr = request.args.get("expr", "0")
    # VULN: eval() sur expression fournie par l'utilisateur
    result = eval(expr)
    return jsonify({"expression": expr, "result": result})


@app.route("/api/secret", methods=["GET"])
def get_secret():
    """Route retournant la clé API hardcodée."""
    return jsonify({"secret_key": SECRET_API_KEY, "debug": DEBUG_MODE})


if __name__ == "__main__":
    app.run(debug=DEBUG_MODE)