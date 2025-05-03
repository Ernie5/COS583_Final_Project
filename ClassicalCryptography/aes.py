from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
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
    padded_text = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return base64.b64encode(ciphertext).decode()

def decrypt(ciphertext_b64: str, key: bytes) -> str:
    """Decrypts Base64 AES-256 ECB ciphertext with PKCS5Padding."""
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_padded = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted_padded, AES.block_size)
    return plaintext.decode()
