import React, { useState, useEffect } from "react";
import axios from "axios";
import "./App.css";

function App() {
  const [blockchain, setBlockchain] = useState([]);
  const [newBlockData, setNewBlockData] = useState("");
  const [isChainValid, setIsChainValid] = useState(null);

  const API_URL = "http://127.0.0.1:5000";

  const fetchBlockchain = async () => {
    try {
      const response = await axios.get(`${API_URL}/get_chain`);
      setBlockchain(response.data.chain);
    } catch (error) {
      console.error("Error fetching blockchain:", error);
    }
  };

  const validateBlockchain = async () => {
    try {
      const response = await axios.get(`${API_URL}/validate_chain`);
      setIsChainValid(response.data.valid);
    } catch (error) {
      console.error("Error validating blockchain:", error);
    }
  };

  const addBlock = async (e) => {
    e.preventDefault();
    if (!newBlockData) return;

    try {
      await axios.post(`${API_URL}/add_block`, { data: newBlockData });
      setNewBlockData("");
      fetchBlockchain();
    } catch (error) {
      console.error("Error adding block:", error);
    }
  };

  useEffect(() => {
    fetchBlockchain();
  }, []);

  return (
    <div className="App">
      <header className="App-header">
        <h1>Blockchain Visualizer</h1>
      </header>

      <main>
        <section>
          <h2>Cadena de Bloques</h2>
          <div className="blockchain">
            {blockchain.map((block, index) => (
              <React.Fragment key={index}>
                <div className={`block ${isChainValid === false ? "invalid" : "valid"}`}>
                  <p><strong>Índice:</strong> {block.index}</p>
                  <p><strong>Hash:</strong> {block.hash}</p>
                  <p><strong>Hash Anterior:</strong> {block.previous_hash}</p>
                  <p><strong>Datos:</strong> {block.data}</p>
                  <p><strong>Nonce:</strong> {block.nonce}</p>
                  <p><strong>Timestamp:</strong> {new Date(block.timestamp * 1000).toLocaleString()}</p>
                </div>
                {index < blockchain.length - 1 && (
                  <div className="chain-connector">➡</div>
                )}
              </React.Fragment>
            ))}
          </div>
        </section>

        <section>
          <h2>Agregar un Nuevo Bloque</h2>
          <form onSubmit={addBlock} className="add-block-form">
            <input
              type="text"
              value={newBlockData}
              onChange={(e) => setNewBlockData(e.target.value)}
              placeholder="Introduce datos para el bloque"
            />
            <button type="submit">Agregar Bloque</button>
          </form>
        </section>

        <section>
          <h2>Validar Blockchain</h2>
          <button onClick={validateBlockchain} className="validate-button">
            Validar Blockchain
          </button>
          {isChainValid !== null && (
            <p className={`validation-message ${isChainValid ? "valid" : "invalid"}`}>
              {isChainValid ? "La blockchain es válida ✅" : "La blockchain es inválida ❌"}
            </p>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;
