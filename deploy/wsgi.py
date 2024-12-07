from main import app

##Implementando cors para toos los origenes

from flask_cors import CORS
CORS(app, resources={r"/*": {"origins": "*"}})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
