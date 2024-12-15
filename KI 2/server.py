import socket
import threading
from implementasides import encrypt, decrypt, pad_text, unpad_text, bit_array_to_string

# Load the shared key
with open("shared_key.bin", "rb") as key_file:
    key = key_file.read()

def handle_client(client_socket, client_address):
    while True:
        encrypted_data = client_socket.recv(4096)
        if not encrypted_data:
            break
        # Decrypt the message received from one client
        encrypted_bits = list(map(int, encrypted_data.decode().strip()))  # Ensure proper decoding
        decrypted_bits = decrypt(encrypted_bits, key)
        decrypted_text = bit_array_to_string(decrypted_bits)
        
        print(f"From {client_address}: {decrypted_text}")
        
        # Send the message to all other clients
        for client in clients:
            if client != client_socket:  # Avoid sending to the sender
                client.send(encrypted_data)

# Setup the server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 65432))
server_socket.listen(2)  # Allow two clients to connect
print("Server ready to accept clients...")

clients = []  # List to keep track of connected clients

while True:
    conn, addr = server_socket.accept()
    clients.append(conn)
    print(f"Connection from {addr}")
    threading.Thread(target=handle_client, args=(conn, addr)).start()
