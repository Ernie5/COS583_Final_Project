import aes_test
import dh_test
import rsa_test
import ecc_test

def main():
    # AES
    aes_test.main()

    # DH
    dh_test.main()

    # RSA
    rsa_test.main()


    # ECC
    ecc_test.main()

if __name__ == '__main__':
    main()