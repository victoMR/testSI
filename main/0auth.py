from flask import Flask, redirect, request
from dotenv import load_dotenv
import os
import requests

# Cargar variables desde .env
load_dotenv()

# Configuración inicial
CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
AUTHORIZATION_BASE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
API_USER_URL = "https://api.github.com/user"
REDIRECT_URI = "https://drake-splendid-albacore.ngrok-free.app/callback"

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route("/")
def index():
    auth_url = f"{AUTHORIZATION_BASE_URL}?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=user"
    return f"<a href='{auth_url}'>Iniciar sesión con GitHub</a>"

@app.route("/callback")
def callback():
    code = request.args.get("code")
    if not code:
        return "Error: No se recibió el código de autorización", 400

    # Intercambiar el código por un token de acceso
    token_response = requests.post(
        TOKEN_URL,
        headers={"Accept": "application/json"},
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": code,
            "redirect_uri": REDIRECT_URI,
        },
    )
    token_data = token_response.json()

    if "access_token" not in token_data:
        return f"Error al obtener el token: {token_data}", 400

    access_token = token_data["access_token"]

    # Obtener información del usuario desde la API de GitHub
    user_response = requests.get(
        API_USER_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    user_data = user_response.json()

    return f"Usuario autenticado: {user_data.get('login')}"

if __name__ == "__main__":
    print(f"Callback URL para GitHub: {REDIRECT_URI}")
    app.run(port=5000)
