import oqs
import time

def benchmark(func, *args):
    """Helper function to measure execution time."""
    start = time.time()
    result = func(*args)
    end = time.time()
    return result, end - start

def ml_kem_demo():
    kem_alg = "ML-KEM-1024"

    print(f" Using PQC Algorithm: {kem_alg}")

    with oqs.KeyEncapsulation(kem_alg) as server:
        public_key, keygen_time = benchmark(server.generate_keypair)

        print(f" Key Generation: {keygen_time:.6f} seconds")

        with oqs.KeyEncapsulation(kem_alg) as client:
            (ciphertext, shared_secret_enc), encap_time = benchmark(client.encap_secret, public_key)

        print(f" Encryption (Encapsulation): {encap_time:.6f} seconds")

        shared_secret_dec, decap_time = benchmark(server.decap_secret, ciphertext)

        print(f" Decryption (Decapsulation): {decap_time:.6f} seconds")

        print(f"\n Shared Secret (Encapsulated):   {shared_secret_enc.hex()}")
        print(f" Shared Secret (Decapsulated):   {shared_secret_dec.hex()}")

        assert shared_secret_enc == shared_secret_dec, " Key Encapsulation Failed!"
        print("\n ML-KEM Key Encapsulation Successful!")

        print(f"\n Public Key (truncated): {public_key.hex()[:64]}...")
        print(f" Ciphertext (truncated): {ciphertext.hex()[:64]}...")
