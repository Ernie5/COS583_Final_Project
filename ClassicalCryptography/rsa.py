from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

def generate_keys_pem(bits=4096):
    """Generate RSA key pair and return them in PEM format."""
    key = RSA.generate(bits)
    private_pem = key.export_key().decode()
    public_pem = key.publickey().export_key().decode()
    return public_pem, private_pem

def encrypt(message, public_pem):
    """Encrypt a message using a PEM-encoded public key."""
    pub_key = RSA.import_key(public_pem)
    cipher = PKCS1_OAEP.new(pub_key)
    encrypted = cipher.encrypt(message.encode())
    return encrypted

def decrypt(ciphertext, private_pem):
    """Decrypt a message using a PEM-encoded private key."""
    priv_key = RSA.import_key(private_pem)
    cipher = PKCS1_OAEP.new(priv_key)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted.decode()

# Example usage
if __name__ == "__main__":
    pub_pem, priv_pem = generate_keys_pem()

    message = "Hello, RSA-PEM!"
    cipher = encrypt(message, pub_pem)
    print("Encrypted:", cipher)
    decrypted_message = decrypt(cipher, priv_pem)

    print("Public Key PEM:\n", pub_pem)
    print("Private Key PEM:\n", priv_pem)
    print(f"Original: {message}")
    print(f"Decrypted: {decrypted_message}")
