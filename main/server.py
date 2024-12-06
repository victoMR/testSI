from flask import Flask, render_template, request, redirect
import os
import requests
from dotenv import load_dotenv

# Cargar variables de entorno desde .env
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

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/callback')
def callback():
    # Obtener el código enviado por GitHub
    code = request.args.get('code')
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

    # Renderizar información del usuario
    return render_template('user.html', user=user_data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
