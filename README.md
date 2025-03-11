# Cryptography Toolkit 🛠️

Welcome to the **Cryptography Toolkit**! This repository is a collection of cryptographic algorithms implemented in Python. Whether you're a hacker, a security enthusiast, or just curious about cryptography, this repo has something for you. Dive into the world of encryption, decryption, and hashing with these tools.

## 🔐 Algorithms Included

### 1. **Hill Cipher**
   - A polygraphic substitution cipher based on linear algebra.
   - **Usage**: Encrypt and decrypt text using a key matrix.
   - **File**: `HILL_CIPHER.PY`

```python
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
```

### 2. **Monoalphabetic Cipher**
   - A substitution cipher where each letter is mapped to a fixed different letter.
   - **Usage**: Encrypt and decrypt text using a randomly generated key.
   - **File**: `MONOALPHABETIC_CIPHER.PY`

```python
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
```

### 3. **Playfair Cipher**
   - A digraph substitution cipher that uses a 5x5 matrix for encryption.
   - **Usage**: Encrypt and decrypt text using a keyword.
   - **File**: `PLAYFAIR_CIPHER.PY`

```python
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
```

### 4. **RSA Encryption**
   - An asymmetric cryptographic algorithm for secure data transmission.
   - **Usage**: Generate RSA keys, encrypt, and decrypt messages.
   - **File**: `RSA.PY`

```python
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(text, public_key):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_bytes = cipher_rsa.encrypt(text.encode())
    return base64.b64encode(encrypted_bytes).decode()

def rsa_decrypt(encrypted_text, private_key):
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_bytes = cipher_rsa.decrypt(base64.b64decode(encrypted_text))
    return decrypted_bytes.decode()

# Generate RSA keys
private_key, public_key = generate_rsa_keys()

# Example usage
text = "Hello, RSA!"

# Encrypting the text
encrypted_text = rsa_encrypt(text, public_key)
print(f"Encrypted: {encrypted_text}")

# Decrypting the text
decrypted_text = rsa_decrypt(encrypted_text, private_key)
print(f"Decrypted: {decrypted_text}")
```

### 5. **SHA-1 Hash**
   - A cryptographic hash function that produces a 160-bit hash value.
   - **Usage**: Generate SHA-1 hashes for any input text.
   - **File**: `SHA1_HASH.PY`

```python
import hashlib

def generate_sha1_hash(text):
    sha1 = hashlib.sha1()
    sha1.update(text.encode())
    return sha1.hexdigest()

# Example usage
text = "Hello, SHA-1!"
hash_output = generate_sha1_hash(text)
print(f"SHA-1 Hash: {hash_output}")
```

### 6. **AES & DES Encryption**
   - Symmetric key algorithms for encryption and decryption.
   - **Usage**: Encrypt and decrypt text using AES or DES.
   - **File**: `AES_DES.PY`

```python
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
import base64

def aes_encrypt(text, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=key)  # Using key as IV for simplicity
    encrypted_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
    return base64.b64encode(encrypted_bytes).decode()

def aes_decrypt(encrypted_text, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    decrypted_bytes = unpad(cipher.decrypt(base64.b64decode(encrypted_text)), AES.block_size)
    return decrypted_bytes.decode()

def des_encrypt(text, key):
    cipher = DES.new(key, DES.MODE_CBC, iv=key)  # Using key as IV for simplicity
    encrypted_bytes = cipher.encrypt(pad(text.encode(), DES.block_size))
    return base64.b64encode(encrypted_bytes).decode()

def des_decrypt(encrypted_text, key):
    cipher = DES.new(key, DES.MODE_CBC, iv=key)
    decrypted_bytes = unpad(cipher.decrypt(base64.b64decode(encrypted_text)), DES.block_size)
    return decrypted_bytes.decode()

# Example usage
key_aes = b"thisisasecretkey"  # 16-byte key for AES-128
key_des = b"8bytekey"  # 8-byte key for DES
text = "Hello, World!"

# AES Encryption & Decryption
encrypted_aes = aes_encrypt(text, key_aes)
print(f"AES Encrypted: {encrypted_aes}")
decrypted_aes = aes_decrypt(encrypted_aes, key_aes)
print(f"AES Decrypted: {decrypted_aes}")

# DES Encryption & Decryption
encrypted_des = des_encrypt(text, key_des)
print(f"DES Encrypted: {encrypted_des}")
decrypted_des = des_decrypt(encrypted_des, key_des)
print(f"DES Decrypted: {decrypted_des}")
```

### 7. **Caesar Cipher**
   - One of the simplest and most widely known encryption techniques.
   - **Usage**: Encrypt and decrypt text using a shift value.
   - **File**: `CAESAR_CIPHER.PY`

```python
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
```

### 8. **Digital Signature**
   - A method for verifying the authenticity of digital messages.
   - **Usage**: Sign messages and verify signatures using RSA.
   - **File**: `DigtalSignature.py`

```python
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def sign_message(message, private_key):
    key = RSA.import_key(private_key)
    hash_obj = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(hash_obj)
    return signature

def verify_signature(message, signature, public_key):
    key = RSA.import_key(public_key)
    hash_obj = SHA256.new(message.encode())
    try:
        pkcs1_15.new(key).verify(hash_obj, signature)
        return "Signature is valid!"
    except (ValueError, TypeError):
        return "Signature is invalid!"

# Generate RSA keys
private_key, public_key = generate_rsa_keys()

# Example usage
message = "Hello, Digital Signature!"
signature = sign_message(message, private_key)

# Verifying the signature
verification_result = verify_signature(message, signature, public_key)

print(f"Original Message: {message}")
print(f"Signature: {signature.hex()}")
print(f"Verification Result: {verification_result}")
```

## 🚀 How to Use

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/MihirSoni2824/CIPHERING.git
   cd CIPHERING
   ```

2. **Run the Scripts**:
   Each script is standalone. Simply run the Python file for the algorithm you want to use.

   Example:
   ```bash
   python3 HILL_CIPHER.PY
   ```

3. **Customize**:
   Modify the input text, keys, or other parameters in the scripts to experiment with different outputs.

## 🧑‍💻 Hacker's Guide

### Why Use This Toolkit?
- **Learn**: Understand how cryptographic algorithms work under the hood.
- **Experiment**: Play around with encryption, decryption, and hashing.
- **Hack**: Use these tools to test security systems or create your own cryptographic challenges.

### Pro Tips:
- Always use strong keys for encryption (e.g., 2048-bit RSA keys).
- Never use insecure algorithms like SHA-1 or DES in production systems.
- Combine multiple algorithms for layered security.

## 🛡️ Disclaimer
This repository is for educational purposes only. Do not use these tools for malicious activities. Always follow ethical guidelines and respect privacy laws.

## 📜 License
This project is licensed under the MIT License. Feel free to use, modify, and distribute the code.

## 💻 Contributing
Contributions are welcome! If you have ideas for new algorithms or improvements, open an issue or submit a pull request.
