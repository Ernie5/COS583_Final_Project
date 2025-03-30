import random
import sympy

# Generate a large prime number
def generate_prime(bits=1024):
    return sympy.randprime(2**(bits-1), 2**bits)

# Compute the modular inverse
def mod_inverse(e, phi):
    return pow(e, -1, phi)

# Generate RSA keys
def generate_rsa_keys():
    bits = 1024
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Common public exponent
    d = mod_inverse(e, phi)
    return (n, e), (n, d)

# Encrypt a message
def encrypt(message, public_key):
    n, e = public_key
    message_int = int.from_bytes(message.encode(), 'big')
    cipher_int = pow(message_int, e, n)
    return cipher_int

# Decrypt a message
def decrypt(cipher_int, private_key):
    n, d = private_key
    message_int = pow(cipher_int, d, n)
    message_bytes = message_int.to_bytes((message_int.bit_length() + 7) // 8, 'big')
    return message_bytes.decode()

# Example usage
public_key, private_key = generate_rsa_keys()
message = "Hello, RSA-2048!"
cipher = encrypt(message, public_key)
decrypted_message = decrypt(cipher, private_key)

print("Original Message:", message)
print("Encrypted Cipher:", cipher)
print("Decrypted Message:", decrypted_message)
