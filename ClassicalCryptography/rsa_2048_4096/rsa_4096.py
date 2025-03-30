import random
import sympy
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

def generate_keys(bits=4096):
    """Generate an RSA key pair with the given bit size."""
    e = 65537  # Commonly used public exponent
    
    # Generate two large prime numbers
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Compute the modular inverse of e modulo phi(n)
    d = inverse(e, phi)
    
    public_key = (n, e)
    private_key = (n, d)
    
    return public_key, private_key

def encrypt(message, public_key):
    """Encrypt a message using the public key."""
    n, e = public_key
    message_int = bytes_to_long(message.encode())
    cipher_int = pow(message_int, e, n)
    return cipher_int

def decrypt(cipher_int, private_key):
    """Decrypt a message using the private key."""
    n, d = private_key
    message_int = pow(cipher_int, d, n)
    message = long_to_bytes(message_int).decode()
    return message

# Example usage
if __name__ == "__main__":
    pub_key, priv_key = generate_keys()
    
    message = "Hello, RSA-4096!"
    cipher = encrypt(message, pub_key)
    decrypted_message = decrypt(cipher, priv_key)
    
    print(f"Original: {message}")
    print(f"Decrypted: {decrypted_message}")