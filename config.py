"""Configuration fictive pour l'application de démo TriagePipe.

ATTENTION: Ces valeurs sont des exemples/placés-holders.
NE PAS utiliser en production. À remplacer par des valeurs
réelles issues de gestionnaires de secrets (Vault, etc.).
"""

# Clés API fictives - exemple seulement
API_KEY = "sk-test-12345678abcdef"
SECRET_API_KEY = "sk-live-51HqJ8kL9mN2pQrStUvWxYzAbCdEfGhIjKlMnOp"

# Token GitHub fictif
GITHUB_PERSONAL_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD"

# Mot de passe base de données fictif
DB_PASSWORD = "super_secret_pwd_12345"

# Environnement
FLASK_ENV = "development"
DEBUG = True

# Note: En production, ces valeurs doivent être lues depuis
# des variables d'environnement externes ou un gestionnaire de secrets.
# NE jamais commit de réelles clés dans le dépôt.