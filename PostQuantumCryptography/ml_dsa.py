import oqs
import time

def benchmark(func, *args):
    """Helper function to measure execution time."""
    start = time.time()
    result = func(*args)
    end = time.time()
    return result, end - start

def ml_dsa_demo():
    dsa_alg = "ML-DSA-87"

    print(f" Using PQC Algorithm: {dsa_alg}")

    with oqs.Signature(dsa_alg) as signer:
        public_key, keygen_time = benchmark(signer.generate_keypair)
        _ = signer.export_secret_key()

        print(f" Key Generation: {keygen_time:.6f} seconds")

        message = b"Post-Quantum Cryptography is the future!"
        signature, sign_time = benchmark(signer.sign, message)

        print(f" Signing: {sign_time:.6f} seconds")

        with oqs.Signature(dsa_alg) as verifier:
            is_valid, verify_time = benchmark(verifier.verify, message, signature, public_key)

        print(f" Verification: {verify_time:.6f} seconds")

        assert is_valid, "Signature Verification Failed!"
        print("\n ML-DSA Signature Successfully Verified!")

        print(f"\n Public Key (truncated): {public_key.hex()[:64]}...")
        print(f" Signature (truncated): {signature.hex()[:64]}...")
        print(f" Original Message: {message.decode()}")