from flask import Flask, jsonify, request
from flask_cors import CORS  # Importar CORS
import hashlib
import time

app = Flask(__name__)
CORS(app)  # Habilitar CORS para todos los orígenes

# Clase para representar un bloque
class Block:
    def __init__(self, index, previous_hash, data, timestamp=None):
        self.index = index
        self.previous_hash = previous_hash
        self.data = data
        self.timestamp = timestamp or time.time()
        self.nonce = 0
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_data = f"{self.index}{self.previous_hash}{self.data}{self.timestamp}{self.nonce}"
        return hashlib.sha256(block_data.encode()).hexdigest()

    def mine_block(self, difficulty):
        target = "0" * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()

# Clase para representar la blockchain
class Blockchain:
    def __init__(self, difficulty=4):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty

    def create_genesis_block(self):
        return Block(0, "0", "Genesis Block")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, data):
        previous_block = self.get_latest_block()
        new_block = Block(len(self.chain), previous_block.hash, data)
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if current_block.hash != current_block.calculate_hash():
                return False
            if current_block.previous_hash != previous_block.hash:
                return False
        return True

# Instanciar la blockchain
blockchain = Blockchain()

# Rutas de la API
@app.route('/get_chain', methods=['GET'])
def get_chain():
    chain_data = []
    for block in blockchain.chain:
        chain_data.append({
            'index': block.index,
            'previous_hash': block.previous_hash,
            'hash': block.hash,
            'data': block.data,
            'timestamp': block.timestamp,
            'nonce': block.nonce
        })
    return jsonify({'chain': chain_data, 'length': len(blockchain.chain)}), 200

@app.route('/add_block', methods=['POST'])
def add_block():
    data = request.json.get('data', '')
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    blockchain.add_block(data)
    return jsonify({'message': 'Block added successfully!', 'block': {
        'index': blockchain.get_latest_block().index,
        'previous_hash': blockchain.get_latest_block().previous_hash,
        'hash': blockchain.get_latest_block().hash,
        'data': blockchain.get_latest_block().data,
        'timestamp': blockchain.get_latest_block().timestamp,
        'nonce': blockchain.get_latest_block().nonce
    }}), 201

@app.route('/validate_chain', methods=['GET'])
def validate_chain():
    is_valid = blockchain.is_chain_valid()
    return jsonify({'valid': is_valid}), 200

# Iniciar la aplicación
if __name__ == "__main__":
    app.run(debug=True)
