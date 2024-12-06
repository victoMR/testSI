from main import app

##Implementando cors para https://test-si-pi.vercel.app/

from flask_cors import CORS
CORS(app, resources={r"/*": {"origins": "https://test-si-pi.vercel.app"}})

if __name__ == '__main__':
    app.run(host='https://testsi.onrender.com/', port=5000)
