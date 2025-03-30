import oqs
import time

def benchmark(func, *args):
    """Helper function to measure execution time."""
    start = time.time()
    result = func(*args)
    end = time.time()
    return result, end - start

def ml_kem_demo():
    # Choose the ML-KEM variant (Kyber-1024 for maximum security)
    kem_alg = "ML-KEM-1024"

    print(f" Using PQC Algorithm: {kem_alg}")

    # Step 1: Key Generation
    with oqs.KeyEncapsulation(kem_alg) as server:
        public_key, keygen_time = benchmark(server.generate_keypair)
        secret_key = server.export_secret_key()

        print(f" Key Generation: {keygen_time:.6f} seconds")

        # Step 2: Client Encrypts a Shared Secret
        with oqs.KeyEncapsulation(kem_alg) as client:
            (shared_secret_enc, ciphertext), encap_time = benchmark(client.encap_secret, public_key)

        print(f" Encryption (Encapsulation): {encap_time:.6f} seconds")

        # Step 3: Server Decrypts the Shared Secret
        shared_secret_dec, decap_time = benchmark(server.decap_secret, ciphertext)

        print(f" Decryption (Decapsulation): {decap_time:.6f} seconds")

        # Verify that both shared secrets match
        assert shared_secret_enc == shared_secret_dec, " Key Encapsulation Failed!"
        print("\n ML-KEM Key Encapsulation Successful!")

        # Displaying important details (truncated for readability)
        print(f"\n Public Key (truncated): {public_key.hex()[:64]}...")
        print(f" Ciphertext (truncated): {ciphertext.hex()[:64]}...")
        print(f" Shared Secret (Encapsulated): {shared_secret_enc.hex()}")
        print(f" Shared Secret (Decapsulated): {shared_secret_dec.hex()}")

# Run the ML-KEM test
ml_kem_demo()
