import socket
import threading
from implementasides import encrypt, decrypt, pad_text, unpad_text, bit_array_to_string
from rsa_utils import load_private_key, decrypt_with_rsa  # Import RSA functions

# Load the RSA private key for the server
private_key = load_private_key()

def handle_client(client_socket, client_address):
    while True:
        encrypted_data = client_socket.recv(4096)
        if not encrypted_data:
            break
        
        # Step 1: Decrypt the DES key using RSA
        encrypted_des_key = encrypted_data[:256]  # Assume first 256 bytes is the encrypted DES key
        encrypted_message = encrypted_data[256:]  # Remaining part is the actual message

        # Debug: Print the length of encrypted DES key and message
        print(f"Encrypted DES key length: {len(encrypted_des_key)} bytes")
        print(f"Encrypted message length: {len(encrypted_message)} bytes")

        # Validate encrypted DES key length
        if len(encrypted_des_key) != 256:
            print("Error: Encrypted DES key has an incorrect length.")
            return  # If the DES key is not the correct size, end the connection

        # Decrypt the DES key with RSA
        try:
            des_key = decrypt_with_rsa(private_key, encrypted_des_key)
            print(f"DES Key: {des_key}")  # Debug print the decrypted DES key
        except Exception as e:
            print(f"Error decrypting DES key: {e}")
            return  # If decryption fails, end the connection

        # Step 2: Decrypt the message using DES (with the DES key)
        try:
            decrypted_bits = decrypt(list(map(int, encrypted_message.decode())), des_key)
            decrypted_text = bit_array_to_string(decrypted_bits)
            unpadded_text = unpad_text(decrypted_text)
            print(f"From {client_address}: {unpadded_text.strip()}")
        except Exception as e:
            print(f"Error decrypting message: {e}")
            return  # If message decryption fails, end the connection

        # Send the message to all other clients
        for client in clients:
            if client != client_socket:
                client.send(encrypted_data)  # Send back the encrypted data


# Server setup
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 65440))
server_socket.listen(2)  # Allow two clients to connect
print("Server ready to accept clients...")

clients = []  # List to keep track of connected clients

while True:
    conn, addr = server_socket.accept()
    clients.append(conn)
    print(f"Connection from {addr}")
    threading.Thread(target=handle_client, args=(conn, addr)).start()
