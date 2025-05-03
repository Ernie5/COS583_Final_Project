from ecdsa import SigningKey, NIST256p, BadSignatureError
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
