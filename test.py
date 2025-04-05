import aes_test
import dh_test
import rsa_test
import ecc_test

def main():
    # AES
    aes_test.speed()
    aes_test.memory()
    aes_test.network()

    # DH
    dh_test.speed()
    dh_test.memory()
    dh_test.network()

    # RSA
    rsa_test.speed()
    rsa_test.memory()
    rsa_test.network()


    # ECC
    ecc_test.speed()
    ecc_test.memory()
    ecc_test.network()

if __name__ == '__main__':
    main()