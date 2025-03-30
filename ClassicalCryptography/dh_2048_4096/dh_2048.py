import secrets
import hashlib

# 2048-bit MODP Group from RFC 3526 (safe prime)
P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
        "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
        "A63A36210000000000090563", 16)  # 2048-bit prime
G = 2  # Generator

class DiffieHellman:
    def __init__(self):
        self.private_key = secrets.randbits(2048)  # Generate a random 2048-bit private key
        self.public_key = pow(G, self.private_key, P)  # Compute public key
    
    def compute_shared_secret(self, other_public_key: int) -> bytes:
        """Computes the shared secret key given another party's public key."""
        shared_secret = pow(other_public_key, self.private_key, P)
        return hashlib.sha256(str(shared_secret).encode()).digest()

# Example usage
alice = DiffieHellman()
bob = DiffieHellman()

# Exchange public keys
alice_shared_secret = alice.compute_shared_secret(bob.public_key)
bob_shared_secret = bob.compute_shared_secret(alice.public_key)

assert alice_shared_secret == bob_shared_secret  # Both should have the same shared secret
print("Shared secret (SHA-256 hashed):", alice_shared_secret.hex())
