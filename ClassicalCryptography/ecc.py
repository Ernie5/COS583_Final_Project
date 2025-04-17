from ecdsa import SigningKey, VerifyingKey, NIST256p, BadSignatureError
from hashlib import sha256
import base64

class ECC_P256:
    def __init__(self):
        self.curve = NIST256p
        self.private_key = SigningKey.generate(curve=self.curve)
        self.public_key = self.private_key.verifying_key
    
    def sign(self, message: bytes):
        hash_msg = sha256(message).digest()
        signature = self.private_key.sign(hash_msg)
        return signature

    def verify(self, message: bytes, signature: bytes) -> bool:
        hash_msg = sha256(message).digest()
        try:
            return self.public_key.verify(signature, hash_msg)
        except BadSignatureError:
            return False

    def run(self, message: str) -> dict:
        msg_bytes = message.encode()
        signature = self.sign(msg_bytes)

        return {
            'Plaintext': message,
            'Private Key (PEM)': self.private_key.to_pem().decode(),
            'Public Key (PEM)': self.public_key.to_pem().decode(),
            'Signature (Base64)': base64.b64encode(signature).decode(),
            'Signature (Hex)': signature.hex()
        }

# === TESTS ===

# print("\n=== Test 1: Signature verification works ===")
# ecc1 = ECC_P256()
# msg1 = b"Hello, ECC-P256!"
# sig1 = ecc1.sign(msg1)
# valid1 = ecc1.verify(msg1, sig1)
# print("Result:", "PASSED" if valid1 else "FAILED")

# print("\n=== Test 2: Signature fails on tampered message ===")
# tampered_msg = b"Hello, altered message!"
# invalid = ecc1.verify(tampered_msg, sig1)
# if not invalid:
#     print("Result: PASSED (tampered signature correctly rejected)")
# else:
#     print("Result: FAILED (tampered signature was incorrectly accepted)")

# print("\n=== Test 3: Verification with recreated public key ===")
# pub_pem = ecc1.public_key.to_pem()
# pub_key = VerifyingKey.from_pem(pub_pem)
# hash_msg = sha256(msg1).digest()
# try:
#     recreated_valid = pub_key.verify(sig1, hash_msg)
#     print("Result:", "PASSED" if recreated_valid else "FAILED")
# except BadSignatureError:
#     print("Result: FAILED (signature could not be verified from PEM)")

# print("\n=== Test 4: Forgery attempt with different key ===")
# ecc2 = ECC_P256()
# forged = ecc2.verify(msg1, sig1)
# if not forged:
#     print("Result: PASSED (forged signature correctly rejected)")
# else:
#     print("Result: FAILED (forged signature was incorrectly accepted)")
