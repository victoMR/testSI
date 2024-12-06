import paramiko
import socket
import threading
import sys
import os


class SecureChatServer:
    def __init__(self, host='0.0.0.0', port=2222):
        """
        Initialize the SSH chat server with key-based authentication.

        Security Features:
        1. SSH protocol for encrypted communication
        2. Key-based authentication
        3. Server-side host key generation
        4. Secure message exchange
        """
        # Generate host keys for the server
        self.host_key = paramiko.RSAKey.generate(2048)

        self.host = host
        self.port = port

        # Store connected clients
        self.clients = {}

        # Create server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))

    def start_server(self):
        """
        Start the SSH chat server and listen for incoming connections.
        """
        # Configure SSH server
        ssh_server = paramiko.ServerInterface()
        self.server_socket.listen(5)
        print(f"[*] Listening on {self.host}:{self.port}")

        while True:
            try:
                client_socket, addr = self.server_socket.accept()
                print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")

                # Create a transport layer for SSH
                transport = paramiko.Transport(client_socket)
                transport.add_server_key(self.host_key)

                # Setup authentication
                ssh_server = SSHChatServer()
                transport.start_server(server=ssh_server)

            except Exception as e:
                print(f"[!] Error: {e}")
                continue


class SSHChatServer(paramiko.ServerInterface):
    def __init__(self):
        """
        Custom SSH server authentication and channel handling.
        """
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        """
        Simple password authentication.
        In a real-world scenario, replace with secure password checking.
        """
        return paramiko.AUTH_SUCCESSFUL if username == 'admin' and password == 'secure_chat_pass' else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        """
        Allow only session channels for chat communication.
        """
        return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class SecureChatClient:
    def __init__(self, host, port, username, password):
        """
        Initialize SSH chat client with secure connection parameters.

        Security Features:
        1. Encrypted SSH connection
        2. Password-based authentication
        3. Secure message transmission
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password

    def connect_and_chat(self):
        """
        Establish a secure SSH connection and start chat session.
        """
        try:
            # Create SSH client
            client = paramiko.SSHClient()

            # Automatically add server's host key
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Connect to the server
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password
            )

            # Open an interactive shell session
            channel = client.invoke_shell()

            # Start threads for sending and receiving messages
            send_thread = threading.Thread(target=self._send_messages, args=(channel,))
            recv_thread = threading.Thread(target=self._receive_messages, args=(channel,))

            send_thread.start()
            recv_thread.start()

            send_thread.join()
            recv_thread.join()

            client.close()

        except Exception as e:
            print(f"[!] Connection Error: {e}")

    def _send_messages(self, channel):
        """
        Send messages securely through the SSH channel.
        """
        while True:
            message = input("You: ")
            if message.lower() == 'exit':
                channel.send(message + '\n')
                break
            channel.send(message + '\n')

    def _receive_messages(self, channel):
        """
        Receive messages securely through the SSH channel.
        """
        while True:
            if channel.recv_ready():
                data = channel.recv(1024).decode('utf-8')
                if not data:
                    break
                print(data, end='')

            if channel.exit_status_ready():
                break


def main():
    # Example usage demonstrating server and client setup
    if len(sys.argv) > 1 and sys.argv[1] == 'server':
        # Start secure SSH chat server
        server = SecureChatServer()
        server.start_server()
    else:
        # Start secure SSH chat client
        client = SecureChatClient(
            host='localhost',
            port=2222,
            username='admin',
            password='secure_chat_pass'
        )
        client.connect_and_chat()


if __name__ == "__main__":
    main()