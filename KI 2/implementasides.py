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


E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

S_BOX = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
		[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
		[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
		[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
	],
	# S4
	[
	    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
		[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
		[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
		[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
	],
	# S5
	[
	    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
		[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
		[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
		[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
	],
	# S6
	[
	    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
		[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
		[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
		[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
	],
	# S7
	[
	    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
		[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
		[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
		[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
	],
	# S8
	[
	    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
		[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
		[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
		[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
	]
]

P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

SHIFT_TABLE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

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
    expanded = permute(right, E)
    xored = xor(expanded, key)
    substituted = s_box_substitution(xored)
    permuted = permute(substituted, P)

    return permuted

def combine_halves(left, right):
    return left + right

def s_box_substitution(expanded_block):
    output = ""
    for i in range(8):
        block = expanded_block[i*6:(i+1)*6]
        row = int(block[0] + block[5], 2)
        col = int(block[1:5], 2)
        output += format(S_BOX[i][row][col], '04b')
    return output

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
    padded_text = pad_text(plain_text)
    bit_array = string_to_bit_array(padded_text)
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
    plain_text_bits = []

    # Process each 64-bit block
    for i in range(0, len(cipher_text), 64):
        block = cipher_text[i:i+64]
        plain_bits = decrypt_block(block, key_bit_array)
        plain_text_bits.extend(plain_bits)

    # Convert decrypted bits to string
    decrypted_text = bit_array_to_string(plain_text_bits)

    # Remove padding
    unpadded_text = unpad_text(decrypted_text)

    return unpadded_text

def pad_text(text):
    padding_len = 8 - (len(text) % 8)
    return text + chr(padding_len) * padding_len

def unpad_text(text):
    padding_len = ord(text[-1])
    return text[:-padding_len]
