import socket
import threading
from implementasides import encrypt, decrypt, bit_array_to_string, unpad_text

# Load the shared key (error handling included)
try:
    with open("shared_key.bin", "rb") as key_file:
        key = key_file.read()
except FileNotFoundError:
    print("Error: Shared key file 'shared_key.bin' not found. Please create it.")
    exit(1)

# Server connection details
HOST = 'localhost'
PORT = 65432

# Create a socket connection to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    client_socket.connect((HOST, PORT))
    print(f"Connected to server at {HOST}:{PORT}")
except ConnectionRefusedError:
    print("Error: Connection failed. Is the server running?")
    exit(1)

def receive_messages():
    """
    Continuously receives encrypted messages from the server,
    decrypts them, and prints them to the console.
    """
    while True:
        encrypted_response = client_socket.recv(4096)
        if not encrypted_response:
            break

        try:
            # Decode encrypted response, handle potential errors
            encrypted_bits = list(map(int, encrypted_response.decode()))

            # Decrypt and convert to string
            decrypted_bits = decrypt(encrypted_bits, key)
            decrypted_text = bit_array_to_string(decrypted_bits)

            print(f"Pesan yang diterima: {decrypted_text}")
        except (ValueError, TypeError) as e:
            print(f"Error: Decryption failed. ({e})")

# Start a thread to receive messages in the background
threading.Thread(target=receive_messages, daemon=True).start()

while True:
    plain_text = input("Masukkan teks untuk dienkripsi dan dikirim (atau ketik 'exit' untuk keluar): ")

    if plain_text.lower() == 'exit':
        break

    # Send message directly to the encrypt function (no need for separate padding)
    cipher_bits = encrypt(plain_text, key)

    # Convert bits to string for sending (optimize if needed)
    cipher_text = ''.join(map(str, cipher_bits))

    client_socket.send(cipher_text.encode())
    print("Pesan terenkripsi telah dikirim.")

# Close the socket connection gracefully
client_socket.close()
print("Disconnected from server.")