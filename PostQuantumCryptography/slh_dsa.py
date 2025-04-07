import oqs
import time

def benchmark(func, *args):
    """Helper function to measure execution time."""
    start = time.time()
    result = func(*args)
    end = time.time()
    return result, end - start

def slh_dsa_demo():
    # Choose the SLH-DSA variant (SPHINCS+-SHAKE-256s-simple)
    # To see different variants
    # print(oqs.get_enabled_sig_mechanisms())
    dsa_alg = "SPHINCS+-SHAKE-256s-simple"

    print(f" Using PQC Algorithm: {dsa_alg}")

    # Step 1: Key Pair Generation
    with oqs.Signature(dsa_alg) as signer:
        public_key, keygen_time = benchmark(signer.generate_keypair)
        secret_key = signer.export_secret_key()

        print(f" Key Generation: {keygen_time:.6f} seconds")

        # Step 2: Sign a Message
        message = b"Post-Quantum Cryptography is the future!"
        signature, sign_time = benchmark(signer.sign, message)

        print(f" Signing: {sign_time:.6f} seconds")

        # Step 3: Verify the Signature
        with oqs.Signature(dsa_alg) as verifier:
            is_valid, verify_time = benchmark(verifier.verify, message, signature, public_key)

        print(f" Verification: {verify_time:.6f} seconds")

        # Verify correctness
        assert is_valid, " Signature Verification Failed!"
        print("\n SLH-DSA Signature Successfully Verified!")

        # Displaying important details (truncated for readability)
        print(f"\n Public Key (truncated): {public_key.hex()[:64]}...")
        print(f" Signature (truncated): {signature.hex()[:64]}...")
        print(f" Original Message: {message.decode()}")

# Run the SLH-DSA test
slh_dsa_demo()
