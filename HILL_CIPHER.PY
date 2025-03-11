import numpy as np
import string

def text_to_numbers(text):
    alphabet = string.ascii_uppercase
    return [alphabet.index(char) for char in text]

def numbers_to_text(numbers):
    alphabet = string.ascii_uppercase
    return ''.join(alphabet[num % 26] for num in numbers)

def hill_cipher_encrypt(text, key_matrix):
    text = text.upper().replace(" ", "")
    while len(text) % key_matrix.shape[0] != 0:
        text += 'X'  # Padding if necessary
    text_numbers = text_to_numbers(text)
    text_matrix = np.array(text_numbers).reshape(-1, key_matrix.shape[0])
    encrypted_matrix = np.dot(text_matrix, key_matrix) % 26
    return numbers_to_text(encrypted_matrix.flatten())

def hill_cipher_decrypt(text, key_matrix):
    from sympy import Matrix
    key_inv = Matrix(key_matrix).inv_mod(26)
    text_numbers = text_to_numbers(text)
    text_matrix = np.array(text_numbers).reshape(-1, key_matrix.shape[0])
    decrypted_matrix = np.dot(text_matrix, np.array(key_inv).astype(int)) % 26
    return numbers_to_text(decrypted_matrix.flatten())

# Example usage
key_matrix = np.array([[6, 24, 1], [13, 16, 10], [20, 17, 15]])  # 3x3 Key matrix
text = "HELLO"

# Encrypting the text
encrypted_text = hill_cipher_encrypt(text, key_matrix)
print(f"Encrypted: {encrypted_text}")

# Decrypting the text
decrypted_text = hill_cipher_decrypt(encrypted_text, key_matrix)
print(f"Decrypted: {decrypted_text}")
