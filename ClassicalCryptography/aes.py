from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import random
import string

def generate_printable_key(length=32) -> str:
    """Generates a 32-character printable ASCII key."""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))

def encrypt(plaintext: str, key: bytes) -> tuple[str, str]:
    """Encrypts a plaintext string using AES-256 CBC mode and returns ciphertext + IV (hex and Base64 respectively)."""
    iv = get_random_bytes(16)  # 16-byte IV for AES
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    
    ciphertext_hex = (iv + ciphertext).hex()  # Combine IV + ciphertext and hex-encode it
    iv_b64 = base64.b64encode(iv).decode()    # Still return IV in Base64 for comparison or devglan
    
    return ciphertext_hex, iv_b64

def decrypt(ciphertext_hex: str, key: bytes) -> str:
    """Decrypts a Hex AES-256 CBC encrypted string (expects IV prepended)."""
    data = bytes.fromhex(ciphertext_hex)
    iv, encrypted_text = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_text), AES.block_size).decode()

# Example usage
if __name__ == "__main__":
    key_str = generate_printable_key()
    key_bytes = key_str.encode()

    print(f"Generated Key (Raw String): {key_str}")
    print(f"Key (Hex): {key_bytes.hex()}")
    print(f"Key (Base64): {base64.b64encode(key_bytes).decode()}")

    plaintext = "Hello, AES-256 with IV and padding!"
    encrypted_hex, iv_b64 = encrypt(plaintext, key_bytes)

    print(f"\nEncrypted (Hex, IV + Ciphertext): {encrypted_hex}")
    print(f"IV (Base64): {iv_b64}")

    decrypted_text = decrypt(encrypted_hex, key_bytes)
    print(f"\nDecrypted: {decrypted_text}")
