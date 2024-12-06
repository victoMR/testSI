import streamlit as st
import paramiko
import threading
import queue
import time
from typing import Optional, Dict, Any


class SSHChatManager:
    def __init__(self):
        # Inicialización de colas para comunicación entre hilos
        self.server_recv_queue = queue.Queue()
        self.client_recv_queue = queue.Queue()
        self.server_send_queue = queue.Queue()
        self.client_send_queue = queue.Queue()

        # Estado de conexiones
        self.server_connected = False
        self.client_connected = False

        # Objetos de conexión SSH
        self.server_ssh: Optional[paramiko.SSHClient] = None
        self.client_ssh: Optional[paramiko.SSHClient] = None

    def connect_server(self, hostname: str, username: str, password: str, port: int = 22):
        """Establecer conexión SSH como servidor"""
        try:
            self.server_ssh = paramiko.SSHClient()
            self.server_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.server_ssh.connect(hostname, port, username, password)
            self.server_connected = True

            # Iniciar hilo para recibir mensajes del servidor
            threading.Thread(target=self._server_receive_messages, daemon=True).start()

            return True
        except Exception as e:
            st.error(f"Error conectando al servidor: {e}")
            return False

    def connect_client(self, hostname: str, username: str, password: str, port: int = 22):
        """Establecer conexión SSH como cliente"""
        try:
            self.client_ssh = paramiko.SSHClient()
            self.client_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client_ssh.connect(hostname, port, username, password)
            self.client_connected = True

            # Iniciar hilo para recibir mensajes del cliente
            threading.Thread(target=self._client_receive_messages, daemon=True).start()

            return True
        except Exception as e:
            st.error(f"Error conectando como cliente: {e}")
            return False

    def _server_receive_messages(self):
        """Hilo para recibir mensajes desde el servidor"""
        try:
            # Establecer canal de comunicación
            channel = self.server_ssh.invoke_shell()
            while self.server_connected:
                if channel.recv_ready():
                    mensaje = channel.recv(1024).decode('utf-8')
                    self.server_recv_queue.put(mensaje)

                # Enviar mensajes si hay en la cola de envío
                if not self.server_send_queue.empty():
                    msg_to_send = self.server_send_queue.get()
                    channel.send(msg_to_send + '\n')

                time.sleep(0.1)
        except Exception as e:
            st.error(f"Error en recepción de servidor: {e}")
            self.server_connected = False

    def _client_receive_messages(self):
        """Hilo para recibir mensajes desde el cliente"""
        try:
            # Establecer canal de comunicación
            channel = self.client_ssh.invoke_shell()
            while self.client_connected:
                if channel.recv_ready():
                    mensaje = channel.recv(1024).decode('utf-8')
                    self.client_recv_queue.put(mensaje)

                # Enviar mensajes si hay en la cola de envío
                if not self.client_send_queue.empty():
                    msg_to_send = self.client_send_queue.get()
                    channel.send(msg_to_send + '\n')

                time.sleep(0.1)
        except Exception as e:
            st.error(f"Error en recepción de cliente: {e}")
            self.client_connected = False

    def send_server_message(self, message: str):
        """Encolar mensaje para enviar al servidor"""
        if self.server_connected:
            self.server_send_queue.put(message)

    def send_client_message(self, message: str):
        """Encolar mensaje para enviar al cliente"""
        if self.client_connected:
            self.client_send_queue.put(message)

    def get_server_messages(self) -> list:
        """Obtener mensajes recibidos del servidor"""
        messages = []
        while not self.server_recv_queue.empty():
            messages.append(self.server_recv_queue.get())
        return messages

    def get_client_messages(self) -> list:
        """Obtener mensajes recibidos del cliente"""
        messages = []
        while not self.client_recv_queue.empty():
            messages.append(self.client_recv_queue.get())
        return messages


def main():
    st.title("Chat SSH Bidireccional")

    # Inicializar gestor de SSH si no existe
    if 'ssh_manager' not in st.session_state:
        st.session_state.ssh_manager = SSHChatManager()
        st.session_state.server_messages = []
        st.session_state.client_messages = []

    # Sección de conexión
    with st.sidebar:
        st.header("Configuración de Conexión")
        connection_type = st.radio("Tipo de Conexión",
                                   ["Servidor", "Cliente"],
                                   key="connection_type")

        # Formulario de conexión
        with st.form("ssh_connection"):
            hostname = st.text_input("Hostname")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            port = st.number_input("Puerto", value=22, min_value=1, max_value=65535)

            submit = st.form_submit_button("Conectar")

        # Proceso de conexión
        if submit:
            try:
                if connection_type == "Servidor":
                    connected = st.session_state.ssh_manager.connect_server(
                        hostname, username, password, port
                    )
                else:
                    connected = st.session_state.ssh_manager.connect_client(
                        hostname, username, password, port
                    )

                if connected:
                    st.success(
                        f"Conexión {'del servidor' if connection_type == 'Servidor' else 'del cliente'} establecida")
            except Exception as e:
                st.error(f"Error de conexión: {e}")

    # Sección de chat
    st.header("Chat SSH")

    # Pestañas para servidor y cliente
    tab1, tab2 = st.tabs(["Servidor", "Cliente"])

    with tab1:
        # Mensajes del servidor
        st.subheader("Mensajes Recibidos (Servidor)")
        server_messages = st.session_state.ssh_manager.get_server_messages()
        for msg in server_messages:
            st.text(msg)

        # Envío de mensajes del servidor
        with st.form("server_message_form"):
            server_msg = st.text_input("Mensaje del Servidor", key="server_input")
            server_send = st.form_submit_button("Enviar Mensaje")

            if server_send and server_msg:
                st.session_state.ssh_manager.send_server_message(server_msg)

    with tab2:
        # Mensajes del cliente
        st.subheader("Mensajes Recibidos (Cliente)")
        client_messages = st.session_state.ssh_manager.get_client_messages()
        for msg in client_messages:
            st.text(msg)

        # Envío de mensajes del cliente
        with st.form("client_message_form"):
            client_msg = st.text_input("Mensaje del Cliente", key="client_input")
            client_send = st.form_submit_button("Enviar Mensaje")

            if client_send and client_msg:
                st.session_state.ssh_manager.send_client_message(client_msg)


if __name__ == "__main__":
    main()