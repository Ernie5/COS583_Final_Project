from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def generate_key():
    """Generates a 256-bit key for AES encryption."""
    return get_random_bytes(32)  # 32 bytes = 256 bits

def encrypt(plaintext: str, key: bytes) -> tuple[str, str]:
    """Encrypts a plaintext string using AES-256 CBC mode and returns ciphertext + IV (both Base64)."""
    iv = get_random_bytes(16)  # AES block size is 16 bytes
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    ciphertext_b64 = base64.b64encode(iv + ciphertext).decode()
    iv_b64 = base64.b64encode(iv).decode()
    return ciphertext_b64, iv_b64

def decrypt(ciphertext: str, key: bytes) -> str:
    """Decrypts an AES-256 CBC encrypted string."""
    data = base64.b64decode(ciphertext)
    iv, encrypted_text = data[:16], data[16:]
    print(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_text), AES.block_size).decode()

# Example Usage
if __name__ == "__main__":
    key = generate_key()
    print(f"Generated Key: {key}")
    print(f"Generated Key (Hex): {key.hex()}")
    key_b64 = base64.b64encode(key).decode()
    print(f"Generated Key (Base64): {key_b64}")
    
    plaintext = "Hello, AES-256!"
    encrypted_text, iv_b64 = encrypt(plaintext, key)
    print(f"Encrypted: {encrypted_text}")
    print(f"IV (Base64): {iv_b64}")
    
    decrypted_text = decrypt(encrypted_text, key)
    print(f"Decrypted: {decrypted_text}")
