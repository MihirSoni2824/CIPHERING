import numpy as np

def create_playfair_matrix(key):
    key = key.replace("J", "I")  # Treat I and J as the same
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    key_matrix = "".join(dict.fromkeys(key + alphabet))
    return np.array(list(key_matrix)).reshape(5, 5)

def find_position(matrix, letter):
    row, col = np.where(matrix == letter)
    return row[0], col[0]

def playfair_cipher(text, matrix, mode='encrypt'):
    text = text.upper().replace("J", "I").replace(" ", "")
    text_pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) and text[i] != text[i+1] else 'X'
        text_pairs.append(a + b)
        i += 2 if i+1 < len(text) and text[i] != text[i+1] else 1
    
    result = ""
    for a, b in text_pairs:
        row_a, col_a = find_position(matrix, a)
        row_b, col_b = find_position(matrix, b)
        if row_a == row_b:
            result += matrix[row_a, (col_a + (1 if mode == 'encrypt' else -1)) % 5]
            result += matrix[row_b, (col_b + (1 if mode == 'encrypt' else -1)) % 5]
        elif col_a == col_b:
            result += matrix[(row_a + (1 if mode == 'encrypt' else -1)) % 5, col_a]
            result += matrix[(row_b + (1 if mode == 'encrypt' else -1)) % 5, col_b]
        else:
            result += matrix[row_a, col_b]
            result += matrix[row_b, col_a]
    
    return result

# Example usage
key = "PLAYFAIR EXAMPLE"
matrix = create_playfair_matrix(key)
text = "Hello World"

# Encrypting the text
encrypted_text = playfair_cipher(text, matrix, mode='encrypt')
print(f"Encrypted: {encrypted_text}")

# Decrypting the text
decrypted_text = playfair_cipher(encrypted_text, matrix, mode='decrypt')
print(f"Decrypted: {decrypted_text}")
