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
