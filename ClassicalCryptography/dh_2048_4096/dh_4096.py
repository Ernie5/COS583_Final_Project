import secrets
from Cryptodome.Util import number

class DiffieHellman:
    def __init__(self, key_size=4096):
        self.key_size = key_size
        self.prime = self.generate_large_prime()
        self.generator = 2  # Common choice for DH
        self.private_key = secrets.randbits(key_size)
        self.public_key = pow(self.generator, self.private_key, self.prime)
    
    def generate_large_prime(self):
        return number.getPrime(self.key_size)
    
    def compute_shared_secret(self, other_public_key):
        return pow(other_public_key, self.private_key, self.prime)

# Example Usage:
if __name__ == "__main__":
    alice = DiffieHellman()
    bob = DiffieHellman()
    
    alice_shared_secret = alice.compute_shared_secret(bob.public_key)
    bob_shared_secret = bob.compute_shared_secret(alice.public_key)
    
    assert alice_shared_secret == bob_shared_secret, "Key exchange failed!"
    print("Shared secret successfully established!")
