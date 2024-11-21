import random

# Initial Permutation (IP)
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

# Final Permutation (FP)
FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

# Permutation function
def permute(block, table):
    return [block[i - 1] for i in table]
 
def string_to_bit_array(text):
    array = list(bin(int.from_bytes(text.encode(), 'big'))[2:])
    while len(array) % 64 != 0:
        array.insert(0, '0')  
    return list(map(int, array))

def bit_array_to_string(bit_array):
    binary = ''.join(map(str, bit_array))
    text_bytes = int(binary, 2).to_bytes((len(binary) + 7) // 8, 'big')
    return text_bytes.decode(errors='ignore')

def xor(t1, t2):
    return [i ^ j for i, j in zip(t1, t2)]

def split_in_half(block):
    return block[:len(block) // 2], block[len(block) // 2:]

def feistel(right, key):
    return xor(right, key[:len(right)])

def combine_halves(left, right):
    return left + right

# Generate a random 64-bit key (8 bytes)
def generate_key():
    key = []
    for i in range(8):  # 64-bit key
        byte = random.randint(0, 255)
        key.append(byte)
    return bytes(key)

# DES encryption function for a single 64-bit block
def encrypt_block(bit_array, key_bit_array):
    permuted_bits = permute(bit_array, IP)
    left, right = split_in_half(permuted_bits)

    for i in range(16):
        new_right = xor(left, feistel(right, key_bit_array)) 
        left = right  
        right = new_right

    combined_bits = combine_halves(left, right)
    return permute(combined_bits, FP)

# DES decryption function for a single 64-bit block
def decrypt_block(cipher_bits, key_bit_array):
    permuted_bits = permute(cipher_bits, IP)
    left, right = split_in_half(permuted_bits)

    for i in range(16):
        new_left = xor(right, feistel(left, key_bit_array)) 
        right = left  
        left = new_left

    combined_bits = combine_halves(left, right)
    return permute(combined_bits, FP)

# Encrypt the plaintext by splitting into 64-bit blocks
def encrypt(plain_text, key):
    key_bit_array = string_to_bit_array(''.join(format(byte, '08b') for byte in key))

    bit_array = string_to_bit_array(plain_text)
    cipher_text = []

    # Process each 64-bit block
    for i in range(0, len(bit_array), 64):
        block = bit_array[i:i+64]
        cipher_bits = encrypt_block(block, key_bit_array)
        cipher_text.extend(cipher_bits)

    return cipher_text

# Decrypt the ciphertext by splitting into 64-bit blocks
def decrypt(cipher_text, key):
    key_bit_array = string_to_bit_array(''.join(format(byte, '08b') for byte in key))
    plain_text = []

    # Process each 64-bit block
    for i in range(0, len(cipher_text), 64):
        block = cipher_text[i:i+64]
        plain_bits = decrypt_block(block, key_bit_array)
        plain_text.extend(plain_bits)

    return plain_text

def pad_text(text):
    padding_len = 8 - (len(text) % 8)
    return text + chr(padding_len) * padding_len

def unpad_text(text):
    padding_len = ord(text[-1])
    return text[:-padding_len]

# Main 
if __name__ == "__main__":
    # Get user input 
    plain_text = input("Enter the plaintext to be encrypted: ")

    # Generate a random 64-bit key
    key = generate_key()

    # Encrypt the plaintext
    cipher_bits = encrypt(plain_text, key)
    print(f"Encrypted Binary: {''.join(map(str, cipher_bits))}")

    # Decrypt the ciphertext
    decrypted_bits = decrypt(cipher_bits, key)
    decrypted_text = bit_array_to_string(decrypted_bits)
    print(f"Decrypted Text: {decrypted_text.strip()}")  # Strip any padding or extra characters