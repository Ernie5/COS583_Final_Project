import aes_test
import dh_test
import rsa_test
import ecc_test
import ml_kem_test
import ml_dsa_test
import slh_dsa_test

def main():
    # AES
    aes_test.main()

    # DH
    dh_test.main()

    # RSA
    rsa_test.main()


    # ECC
    ecc_test.main()

    # ML KEM
    ml_kem_test.main()

    # ML DSA
    ml_dsa_test.main()

    # SLH DSA
    slh_dsa_test.main()
    print("\n=== All tests completed successfully! ===\n")

if __name__ == '__main__':
    main()