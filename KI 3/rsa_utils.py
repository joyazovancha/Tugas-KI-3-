# rsa_utils.py

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# Generate RSA public/private key pair
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Save the RSA keys to files
def save_rsa_keys():
    private_key, public_key = generate_rsa_keys()
    with open('rsa_private.pem', 'wb') as f:
        f.write(private_key)
    with open('rsa_public.pem', 'wb') as f:
        f.write(public_key)

# Load the RSA public key
def load_public_key():
    with open('rsa_public.pem', 'rb') as f:
        public_key = RSA.import_key(f.read())
    return public_key

# Load the RSA private key
def load_private_key():
    with open('rsa_private.pem', 'rb') as f:
        private_key = RSA.import_key(f.read())
    return private_key

# Encrypt data using RSA public key
def encrypt_with_rsa(public_key, data):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher_rsa.encrypt(data)
    return encrypted_data

# Decrypt data using RSA private key
def decrypt_with_rsa(private_key, encrypted_data):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher_rsa.decrypt(encrypted_data)
    return decrypted_data
