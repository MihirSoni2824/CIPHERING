import random
import string

def generate_key():
    letters = list(string.ascii_lowercase)
    shuffled = letters[:]
    random.shuffle(shuffled)
    return dict(zip(letters, shuffled)), dict(zip(shuffled, letters))

def monoalphabetic_cipher(text, key, mode='encrypt'):
    result = ""
    for char in text:
        if char.isalpha():
            lower_char = char.lower()
            transformed_char = key[lower_char]
            result += transformed_char.upper() if char.isupper() else transformed_char
        else:
            result += char
    return result

# Generate encryption and decryption keys
encrypt_key, decrypt_key = generate_key()

# Example usage
text = "Hello, World!"

# Encrypting the text
encrypted_text = monoalphabetic_cipher(text, encrypt_key, mode='encrypt')
print(f"Encrypted: {encrypted_text}")

# Decrypting the text
decrypted_text = monoalphabetic_cipher(encrypted_text, decrypt_key, mode='decrypt')
print(f"Decrypted: {decrypted_text}")
