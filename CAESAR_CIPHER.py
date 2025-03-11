def caesar_cipher(text, shift, mode='encrypt'):
    result = ""
    if mode == 'decrypt':
        shift = -shift  # Reverse shift for decryption
    
    for char in text:
        if char.isalpha():  # Encrypt only letters
            shift_base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char  # Keep non-alphabetic characters unchanged
    
    return result

# Example usage
text = "Hello, World!"
shift = 3

# Encrypting the text
encrypted_text = caesar_cipher(text, shift, mode='encrypt')
print(f"Encrypted: {encrypted_text}")

# Decrypting the text
decrypted_text = caesar_cipher(encrypted_text, shift, mode='decrypt')
print(f"Decrypted: {decrypted_text}")
