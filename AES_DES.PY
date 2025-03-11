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
