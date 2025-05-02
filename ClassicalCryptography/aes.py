from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad  # <--- Padding functions
from Crypto.Random import get_random_bytes
import base64
import random
import string

def generate_printable_key(length=32):
    """Generates a 32-character printable key using ASCII letters and digits."""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))

def encrypt(plaintext: str, key: bytes) -> str:
    """Encrypts plaintext using AES-256 in ECB mode with PKCS5Padding."""
    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = pad(plaintext.encode(), AES.block_size)  # Apply PKCS5 (16-byte) padding
    ciphertext = cipher.encrypt(padded_text)
    return base64.b64encode(ciphertext).decode()

def decrypt(ciphertext_b64: str, key: bytes) -> str:
    """Decrypts Base64 AES-256 ECB ciphertext with PKCS5Padding."""
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_padded = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted_padded, AES.block_size)  # Remove padding
    return plaintext.decode()

# Example usage
if __name__ == "__main__":
    key = generate_printable_key()
    print(f"Generated Key: {key}")

    plaintext = "Hello, world! AES with PKCS5Padding works! Hello!"
    print(f"Plaintext: {plaintext}")

    encrypted = encrypt(plaintext, key.encode())
    print(f"Encrypted (Base64): {encrypted}")

    decrypted = decrypt(encrypted, key.encode())
    print(f"Decrypted: {decrypted}")
