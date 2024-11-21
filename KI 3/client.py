# client.py
import socket
import threading
from implementasides import encrypt, pad_text, decrypt, bit_array_to_string, unpad_text
from rsa_utils import load_public_key, encrypt_with_rsa  # Import RSA functions
from Crypto.Random import get_random_bytes


# Load the RSA public key for the server
public_key = load_public_key()

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 65440))

def receive_messages():
    while True:
        encrypted_response = client_socket.recv(4096)
        if not encrypted_response:
            break
        encrypted_bits = list(map(int, encrypted_response.decode()))
        decrypted_bits = decrypt(encrypted_bits, des_key)
        decrypted_text = bit_array_to_string(decrypted_bits)
        unpadded_text = unpad_text(decrypted_text)
        print(f"Pesan yang diterima: {unpadded_text.strip()}")

# Start a thread to receive messages
threading.Thread(target=receive_messages, daemon=True).start()

# Encrypt and send message
while True:
    plain_text = input("Masukkan teks untuk dienkripsi dan dikirim (atau ketik 'exit' untuk keluar): ")
    if plain_text.lower() == 'exit':
        break
    
    padded_text = pad_text(plain_text)
    des_key = get_random_bytes(8)  # Generate a new DES key
    cipher_bits = encrypt(padded_text, des_key)
    cipher_text = ''.join(map(str, cipher_bits))
    
    # Step 1: Encrypt the DES key using RSA
    encrypted_des_key = encrypt_with_rsa(public_key, des_key)
    
    # Step 2: Send the encrypted DES key and message
    client_socket.send(encrypted_des_key + cipher_text.encode())
    print("Pesan terenkripsi telah dikirim.")

client_socket.close()
