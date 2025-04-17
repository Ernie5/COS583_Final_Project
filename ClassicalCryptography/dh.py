import secrets
from Crypto.Random import random
from Crypto.Util import number

class DiffieHellman:
    def __init__(self, generator, prime, key_size):
        self.key_size = key_size
        self.generator = generator
        self.prime = prime
        print(key_size, generator, prime)
        self.private_key = secrets.randbits(key_size)
        self.public_key = pow(self.generator, self.private_key, self.prime)
    
    def get_private(self):
        return self.private_key
    
    def get_public(self):
        return self.public_key

    def compute_shared_secret(self, other_public_key):
        print('computing shared secret')
        return pow(other_public_key, self.private_key, self.prime)

def generate_large_prime(key_size):
    return number.getPrime(key_size)

# Example Usage:
if __name__ == "__main__":
    key_size = 10
    prime = generate_large_prime(key_size)
    generator = 2
    alice = DiffieHellman(generator, prime, key_size)
    bob = DiffieHellman(generator, prime, key_size)

    print(f'alice private key: {alice.get_private()}')
    print(f'alice public key: {bob.get_public()}')

    print(f'bob private key: {bob.get_private()}')
    print(f'bob public key: {bob.get_public()}')
    
    alice_shared_secret = alice.compute_shared_secret(bob.public_key)
    bob_shared_secret = bob.compute_shared_secret(alice.public_key)
    
    assert alice_shared_secret == bob_shared_secret, "Key exchange failed!"
    print("Shared secret successfully established!")
