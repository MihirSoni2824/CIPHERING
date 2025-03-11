import hashlib

def generate_sha1_hash(text):
    sha1 = hashlib.sha1()
    sha1.update(text.encode())
    return sha1.hexdigest()

# Example usage
text = "Hello, SHA-1!"
hash_output = generate_sha1_hash(text)
print(f"SHA-1 Hash: {hash_output}")
