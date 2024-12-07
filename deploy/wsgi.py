from main import app
from flask_cors import CORS

# Habilir CORS para * (todos los dominios)

CORS(app)

if __name__ == '__main__':
    app.run(host='https://testsi-1.onrender.com', port=5000)