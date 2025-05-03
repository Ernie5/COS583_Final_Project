from Crypto.Util.number import getPrime, inverse
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

def generate_keys(bits=4096):
    """Generate RSA keys as (n, e), (n, d), and convert to PEM."""
    e = 65537
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)

    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = inverse(q, p)

    pub_numbers = rsa.RSAPublicNumbers(e, n)
    priv_numbers = rsa.RSAPrivateNumbers(
        p=p, q=q, d=d, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp,
        public_numbers=pub_numbers
    )
    private_key = priv_numbers.private_key(backend=default_backend())
    public_key = private_key.public_key()

    # Convert to PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return public_pem, private_pem


def str_public(public_pem):
    public_pem_str = public_pem.replace('\n', '')
    first_nl_pos = 26
    second_nl_pos = len(public_pem_str) - 24
    public_pem_str = public_pem_str[:second_nl_pos] + '\n' + public_pem_str[second_nl_pos:]
    public_pem_str = public_pem_str[:first_nl_pos] + '\n' + public_pem_str[first_nl_pos:]
    return public_pem_str

def str_private(private_pem):
    private_pem_str = private_pem.replace('\n', '')
    first_nl_pos = 31
    second_nl_pos = len(private_pem_str) - 29
    private_pem_str = private_pem_str[:second_nl_pos] + '\n' + private_pem_str[second_nl_pos:]
    private_pem_str = private_pem_str[:first_nl_pos] + '\n' + private_pem_str[first_nl_pos:]
    return private_pem_str

def encrypt(message, public_pem):
    """Encrypt a message using PEM public key."""
    public_key = serialization.load_pem_public_key(
        public_pem.encode(),
        backend=default_backend()
    )
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.PKCS1v15()
    )
    return ciphertext

def decrypt(ciphertext, private_pem):
    """Decrypt a message using PEM private key."""
    private_key = serialization.load_pem_private_key(
        private_pem.encode(),
        password=None,
        backend=default_backend()
    )
    message = private_key.decrypt(
        ciphertext,
        padding.PKCS1v15()
    )
    return message.decode()

def encode_cipher(cipher):
    return base64.b64encode(cipher).decode()
