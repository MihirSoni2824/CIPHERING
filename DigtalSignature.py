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
