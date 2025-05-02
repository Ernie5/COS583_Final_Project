#!/usr/bin/env python3
# app.py
# Flask crypto playground – now with decrypt support for AES-256-ECB and RSA.

from flask import Flask, render_template, request, send_file
import base64
import oqs
import os, sys
from io import BytesIO

# ───────────────────────────────────────
#  Local imports (your existing modules)
# ───────────────────────────────────────
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(project_root, 'ClassicalCryptography'))
sys.path.append(os.path.join(project_root, 'PostQuantumCryptography'))

import aes, rsa, dh, ecc                       # classical
import ml_kem, ml_dsa, slh_dsa                 # PQC

# Helpers for RSA PEM ⇆ key objects
from Crypto.PublicKey import RSA as CryptoRSA

import textwrap, re

def sanitize_pem(pem: str, is_private=True) -> str:
    """
    Make a best-effort attempt to restore a single-line or mangled PEM
    into a valid multi-line PEM block that cryptography can load.
    """
    pem = pem.strip()

    # Detect header / footer
    header_prv = "-----BEGIN RSA PRIVATE KEY-----"
    footer_prv = "-----END RSA PRIVATE KEY-----"
    header_pub = "-----BEGIN PUBLIC KEY-----"
    footer_pub = "-----END PUBLIC KEY-----"

    header = header_prv if is_private else header_pub
    footer = footer_prv if is_private else footer_pub

    # Remove any existing header/footer + whitespace
    body = re.sub(r"-----.*?KEY-----", "", pem, flags=re.DOTALL)
    body = re.sub(r"\s+", "", body)  # kill all whitespace

    # Re-wrap at 64 chars
    body_wrapped = "\n".join(textwrap.wrap(body, 64))

    return f"{header}\n{body_wrapped}\n{footer}\n"


def pem_to_priv(pem: str):
    """Return a CryptoRSA private-key object from PEM string."""
    return CryptoRSA.import_key(pem.encode())

# Provide rsa.decode_cipher() if your own rsa.py does not have it
if not hasattr(rsa, 'decode_cipher'):
    rsa.decode_cipher = lambda b64: base64.b64decode(b64)

if not hasattr(rsa, 'encode_cipher'):
    rsa.encode_cipher = lambda raw: base64.b64encode(raw).decode()

# ───────────────────────────────────────
app = Flask(__name__)

@app.route('/')
def index():
    """Show main form."""
    return render_template('index.html')

# ───────────────────────────────────────
#  Single endpoint – handles encrypt OR decrypt
# ───────────────────────────────────────
@app.route('/crypto', methods=['POST'])
def crypto():
    algorithm = request.form['algorithm']        # aes, rsa, ecc, …
    operation = request.form.get('operation', 'encrypt')
    message   = request.form.get('message', '')  # may be blank for decrypt paths
    result    = {}

    # ──────────── AES (ECB) ────────────
    if algorithm == 'aes':
        if operation == 'encrypt':
            key         = aes.generate_printable_key()
            ciphertext  = aes.encrypt(message, key.encode())
            result = {
                'Algorithm'  : 'AES-256-ECB',
                'Operation'  : 'Encrypt',
                'Plaintext'  : message,
                'Key (ASCII)': key,
                'Ciphertext (Base64)': ciphertext,
                'Padding'    : 'PKCS#5/PKCS#7'
            }

        else:  # decrypt
            key_ascii   = request.form['aes_key']
            cipher_b64  = request.form['aes_cipher']
            try:
                plaintext  = aes.decrypt(cipher_b64, key_ascii.encode())
                result = {
                    'Algorithm'  : 'AES-256-ECB',
                    'Operation'  : 'Decrypt',
                    'Key (ASCII)': key_ascii,
                    'Ciphertext (Base64)': cipher_b64,
                    'Plaintext'  : plaintext,
                }
            except Exception as exc:
                result = {'Error': f'Decryption failed: {exc}'}

    # ──────────── RSA ────────────
    elif algorithm == 'rsa':
        if operation == 'encrypt':
            pub_key, priv_key = rsa.generate_keys()
            cipher_raw   = rsa.encrypt(message, pub_key)
            cipher_b64   = rsa.encode_cipher(cipher_raw)
            result = {
                'Algorithm'  : 'RSA',
                'Operation'  : 'Encrypt',
                'Plaintext'  : message,
                'Ciphertext (Base64)': cipher_b64,
                'Public Key (PEM)' : rsa.str_public(pub_key),
                'Private Key (PEM)': rsa.str_private(priv_key),
                'Padding'    : 'PKCS#1 v1.5'
            }

        else:  # decrypt
            # grab user inputs
            cipher_b64 = request.form['rsa_cipher']           # Base64 string
            priv_pem   = sanitize_pem(request.form['rsa_priv'])  # fixed-up PEM

            try:
                cipher_raw = rsa.decode_cipher(cipher_b64)    # bytes
                plaintext  = rsa.decrypt(cipher_raw, priv_pem)  # use PEM string

                result = {
                    'Algorithm'           : 'RSA',
                    'Operation'           : 'Decrypt',
                    'Ciphertext (Base64)' : cipher_b64,
                    'Plaintext'           : plaintext,
                }

            except Exception as exc:
                result = {'Error': f'Decryption failed: {exc}'}

    # ──────────── Diffie-Hellman key-exchange demo ────────────
    elif algorithm == 'dh':
        key_size  = 256
        generator = 2
        prime     = dh.generate_large_prime(key_size)

        alice = dh.DiffieHellman(generator, prime, key_size)
        bob   = dh.DiffieHellman(generator, prime, key_size)

        alice_shared = alice.compute_shared_secret(bob.public_key)
        bob_shared   = bob.compute_shared_secret(alice.public_key)

        result = {
            'Algorithm' : 'Diffie-Hellman',
            'Key Size'  : f'{key_size} bits',
            'Prime (truncated)': str(prime)[:64] + '...',
            'Generator' : generator,
            'Alice Public Key': alice.public_key,
            'Bob Public Key'  : bob.public_key,
            'Shared Secret Match': alice_shared == bob_shared
        }

    # ──────────── ECC (sign/verify demo) ────────────
    elif algorithm == 'ecc':
        ecc_obj = ecc.ECC_P256()
        result  = ecc_obj.run(message)
        original_sig  = base64.b64decode(result['Signature (Base64)'])
        is_valid_orig = ecc_obj.verify(message.encode(), original_sig)
        tampered_msg  = message + ' (tampered)'
        is_valid_tamp = ecc_obj.verify(tampered_msg.encode(), original_sig)
        forged_ecc    = ecc.ECC_P256()
        forged_sig    = forged_ecc.sign(message.encode())
        is_valid_forg = ecc_obj.verify(message.encode(), forged_sig)

        result.update({
            'Algorithm' : 'ECC-P256',
            'Signature Valid (original)': is_valid_orig,
            'Signature Valid (tampered)': is_valid_tamp,
            'Signature Valid (forged key)': is_valid_forg,
            'Tampered Message': tampered_msg
        })

    # ──────────── ML-DSA ────────────
    elif algorithm == 'ml_dsa':
        dsa_alg = 'ML-DSA-87'
        with oqs.Signature(dsa_alg) as signer:
            pub_key   = signer.generate_keypair()
            signature = signer.sign(message.encode())
            with oqs.Signature(dsa_alg) as verifier:
                is_valid_orig = verifier.verify(message.encode(), signature, pub_key)
                is_valid_tamp = verifier.verify((message + ' (tampered)').encode(),
                                                signature, pub_key)
                forged_pub    = signer.generate_keypair()
                forged_sig    = signer.sign(message.encode())
                is_valid_forg = verifier.verify(message.encode(), forged_sig, pub_key)

        result = {
            'Algorithm': dsa_alg,
            'Signature Valid (original)': is_valid_orig,
            'Signature Valid (tampered)': is_valid_tamp,
            'Signature Valid (forged key)': is_valid_forg,
            'Public Key (hex, truncated)': pub_key.hex()[:64] + '...',
            'Signature (hex, truncated)' : signature.hex()[:64] + '...'
        }

    # ──────────── SLH-DSA (SPHINCS+) ────────────
    elif algorithm == 'slh_dsa':
        dsa_alg = 'SPHINCS+-SHAKE-256s-simple'
        with oqs.Signature(dsa_alg) as signer:
            pub_key   = signer.generate_keypair()
            signature = signer.sign(message.encode())
            with oqs.Signature(dsa_alg) as verifier:
                is_valid_orig = verifier.verify(message.encode(), signature, pub_key)
                is_valid_tamp = verifier.verify((message + ' (tampered)').encode(),
                                                signature, pub_key)
                forged_sig    = signer.sign(message.encode())
                is_valid_forg = verifier.verify(message.encode(), forged_sig, pub_key)

        result = {
            'Algorithm': dsa_alg,
            'Signature Valid (original)': is_valid_orig,
            'Signature Valid (tampered)': is_valid_tamp,
            'Signature Valid (forged key)': is_valid_forg,
            'Public Key (hex, truncated)': pub_key.hex()[:64] + '...',
            'Signature (hex, truncated)' : signature.hex()[:64] + '...'
        }

    # ──────────── ML-KEM ────────────
    elif algorithm == 'ml_kem':
        kem_alg = 'ML-KEM-1024'
        with oqs.KeyEncapsulation(kem_alg) as server:
            pub_key = server.generate_keypair()
            with oqs.KeyEncapsulation(kem_alg) as client:
                ciphertext, shared_enc = client.encap_secret(pub_key)
            shared_dec = server.decap_secret(ciphertext)
        result = {
            'Algorithm'  : kem_alg,
            'Shared Secret Match': shared_enc == shared_dec,
            'Public Key (hex, truncated)': pub_key.hex()[:64] + '...',
            'Ciphertext (hex, truncated)': ciphertext.hex()[:64] + '...',
            'Shared Secret (Enc)': shared_enc.hex()[:32] + '...',
            'Shared Secret (Dec)': shared_dec.hex()[:32] + '...',
        }

    else:
        result = {'Error': f'Unsupported algorithm: {algorithm}'}

    return render_template('result.html', result=result)

# ───────────────────────────────────────
#  “Download as file” helper
# ───────────────────────────────────────
@app.route('/download', methods=['POST'])
def download():
    content  = request.form['content']
    filename = request.form['filename']
    buffer   = BytesIO(content.encode())
    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
                     download_name=filename, mimetype='text/plain')

# ───────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=True)
