from flask import Flask, render_template, request, send_file
import base64
import oqs
import os
import sys
from io import BytesIO

app = Flask(__name__)

# Setup paths
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(project_root, 'ClassicalCryptography'))
sys.path.append(os.path.join(project_root, 'PostQuantumCryptography'))

# Import your crypto modules
import aes, rsa, dh, ecc
import ml_kem, ml_dsa, slh_dsa

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    algorithm = request.form['algorithm']
    message = request.form['message']
    result = ""

    if algorithm == 'aes':
        key = aes.generate_key()
        encrypted, iv_b64 = aes.encrypt(message, key)
        key_b64 = base64.b64encode(key).decode()
        key_hex = key.hex()

        decrypted = aes.decrypt(encrypted, key)
        result = {
            'AES Key (Base64, 256-bit)': key_b64,
            'AES Key (Hex, 256-bit)': key_hex,
            'IV (Base64)': iv_b64,
            'Encrypted (Base64, IV+ciphertext)': encrypted,
            'Decrypted': decrypted,
            'Key': key,
            'Key length (bytes)': len(key),
            'Key length (Base64)': len(key_b64),
            'IV length (Base64)': len(iv_b64),
        }

    elif algorithm == 'dh':
        key_size = 256
        generator = 2
        prime = dh.generate_large_prime(key_size)

        alice = dh.DiffieHellman(generator, prime, key_size)
        bob = dh.DiffieHellman(generator, prime, key_size)

        alice_shared = alice.compute_shared_secret(bob.public_key)
        bob_shared = bob.compute_shared_secret(alice.public_key)

        result = {
            'Key Size': f"{key_size} bits",
            'Prime (truncated)': str(prime)[:64] + "...",
            'Generator': str(generator),
            'Alice Public Key': str(alice.public_key),
            'Bob Public Key': str(bob.public_key),
            'Shared Secret Match': str(alice_shared == bob_shared),
            'Shared Secret (truncated)': str(alice_shared)[:64] + "..."
        }

    elif algorithm == 'rsa':
        public_key, private_key = rsa.generate_keys()
        encrypted = rsa.encrypt(message, public_key)
        decrypted = rsa.decrypt(encrypted, private_key)
        result = {
            'encrypted': rsa.encode_cipher(encrypted),
            'decrypted': decrypted,
            'public_key': rsa.str_public(public_key),
            'private_key': rsa.str_private(private_key)
        }

    elif algorithm == 'ecc':
        ecc_obj = ecc.ECC_P256()
        result = ecc_obj.run(message)

        original_signature = base64.b64decode(result['Signature (Base64)'])
        original_message_bytes = message.encode()

        # Verify on original message with original key
        is_valid_original = ecc_obj.verify(original_message_bytes, original_signature)

        # Tampered message test
        tampered_message = message + " (tampered)"
        is_valid_tampered = ecc_obj.verify(tampered_message.encode(), original_signature)

        # Forged signature: create new key pair, sign same message, and try to verify using original public key
        forged_ecc = ecc.ECC_P256()
        forged_signature = forged_ecc.sign(original_message_bytes)
        is_valid_forged = ecc_obj.verify(original_message_bytes, forged_signature)

        result.update({
            'Algorithm': 'ECC-P256 (NIST Curve)',
            'Signature Valid (Original)': str(is_valid_original),
            'Signature Valid (Tampered)': str(is_valid_tampered),
            'Signature Valid (Forged with Different Key)': str(is_valid_forged),
            'Tampered Message': tampered_message
        })

    elif algorithm == 'ml_dsa':
        dsa_alg = "ML-DSA-87"
        with oqs.Signature(dsa_alg) as signer:
            public_key = signer.generate_keypair()
            signature = signer.sign(message.encode())
            with oqs.Signature(dsa_alg) as verifier:
                is_valid = verifier.verify(message.encode(), signature, public_key)

            result = {
                'Algorithm': dsa_alg,
                'Signature Valid': str(is_valid),
                'Message': message,
                'Public Key (hex, truncated)': public_key.hex()[:64] + "...",
                'Signature (hex, truncated)': signature.hex()[:64] + "..."
            }

    elif algorithm == 'slh_dsa':
        dsa_alg = "SPHINCS+-SHAKE-256s-simple"
        with oqs.Signature(dsa_alg) as signer:
            public_key = signer.generate_keypair()
            signature = signer.sign(message.encode())
            with oqs.Signature(dsa_alg) as verifier:
                is_valid = verifier.verify(message.encode(), signature, public_key)

            result = {
                'Algorithm': dsa_alg,
                'Signature Valid': str(is_valid),
                'Message': message,
                'Public Key (hex, truncated)': public_key.hex()[:64] + "...",
                'Signature (hex, truncated)': signature.hex()[:64] + "..."
            }

    elif algorithm == 'ml_kem':
        kem_alg = "ML-KEM-1024"
        with oqs.KeyEncapsulation(kem_alg) as server:
            public_key = server.generate_keypair()
            with oqs.KeyEncapsulation(kem_alg) as client:
                ciphertext, shared_secret_enc = client.encap_secret(public_key)
            shared_secret_dec = server.decap_secret(ciphertext)

            result = {
                'Algorithm': kem_alg,
                'Shared Secret Match': str(shared_secret_enc == shared_secret_dec),
                'Public Key (hex, truncated)': public_key.hex()[:64] + "...",
                'Ciphertext (hex, truncated)': ciphertext.hex()[:64] + "...",
                'Shared Secret (Encapsulated, hex)': shared_secret_enc.hex(),
                'Shared Secret (Decapsulated, hex)': shared_secret_dec.hex()
            }

    return render_template('result.html', result=result)

@app.route('/download', methods=['POST'])
def download():
    content = request.form['content']
    filename = request.form['filename']

    buffer = BytesIO()
    buffer.write(content.encode())
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype='text/plain')

if __name__ == '__main__':
    app.run(debug=True)
