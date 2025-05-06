import secrets
from Crypto.Util import number

class DiffieHellman:
    def __init__(self, generator, prime, key_size):
        self.key_size = key_size
        self.generator = generator
        self.prime = prime
        #print(key_size, generator, prime)
        self.private_key = secrets.randbits(key_size)
        self.public_key = pow(self.generator, self.private_key, self.prime)
    
    def get_private(self):
        return self.private_key
    
    def get_public(self):
        return self.public_key

    def compute_shared_secret(self, other_public_key):
        return pow(other_public_key, self.private_key, self.prime)

def generate_large_prime(key_size):
    return number.getPrime(key_size)
