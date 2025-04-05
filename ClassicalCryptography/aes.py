from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def generate_key():
    """Generates a 256-bit key for AES encryption."""
    return get_random_bytes(32)  # 32 bytes = 256 bits

def encrypt(plaintext: str, key: bytes) -> str:
    """Encrypts a plaintext string using AES-256 CBC mode."""
    iv = get_random_bytes(16)  # AES block size is 16 bytes
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(iv + ciphertext).decode()

def decrypt(ciphertext: str, key: bytes) -> str:
    """Decrypts an AES-256 CBC encrypted string."""
    data = base64.b64decode(ciphertext)
    iv, encrypted_text = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_text), AES.block_size).decode()

# Example Usage
if __name__ == "__main__":
    key = generate_key()
    print(f"Generated Key (Base64): {base64.b64encode(key).decode()}")
    
    plaintext = "Hello, AES-256!"
    encrypted_text = encrypt(plaintext, key)
    print(f"Encrypted: {encrypted_text}")
    
    decrypted_text = decrypt(encrypted_text, key)
    print(f"Decrypted: {decrypted_text}")