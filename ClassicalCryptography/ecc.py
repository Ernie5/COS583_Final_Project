from ecdsa import SigningKey, VerifyingKey, NIST256p
from hashlib import sha256

class ECC_P256:
    def __init__(self):
        self.curve = NIST256p
        self.private_key = SigningKey.generate(curve=self.curve)
        self.public_key = self.private_key.verifying_key
    
    def sign(self, message: bytes):
        hash_msg = sha256(message).digest()
        signature = self.private_key.sign(hash_msg)
        return signature
    
    def verify(self, message: bytes, signature: bytes):
        hash_msg = sha256(message).digest()
        return self.public_key.verify(signature, hash_msg)

# Example Usage
# ecc = ECC_P256()
# message = b"Hello, ECC-P256!"
# signature = ecc.sign(message)
# print("Signature:", signature.hex())

# is_valid = ecc.verify(message, signature)
# print("Signature Valid:", is_valid)