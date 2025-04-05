import timeit
import tracemalloc
import socket
import threading
import sys
import os

# Setup import path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(project_root, 'ClassicalCryptography'))

from rsa import generate_keys, encrypt, decrypt

# --- SPEED TEST ---

def speed(message: str, bits: int = 2048):
    print("Running RSA speed test...")
    
    keygen_time = timeit.timeit(lambda: generate_keys(bits), number=1)
    pub_key, priv_key = generate_keys(bits)

    enc_time = timeit.timeit(lambda: encrypt(message, pub_key), number=100)
    cipher = encrypt(message, pub_key)
    dec_time = timeit.timeit(lambda: decrypt(cipher, priv_key), number=100)

    print(f"Key generation time: {keygen_time:.6f} sec")
    print(f"Avg encryption time: {enc_time / 100:.6f} sec")
    print(f"Avg decryption time: {dec_time / 100:.6f} sec")

# --- MEMORY TEST ---

def memory(message: str, bits: int = 2048):
    print("Running RSA memory test...")
    tracemalloc.start()

    pub_key, priv_key = generate_keys(bits)
    cipher = encrypt(message, pub_key)
    current, peak = tracemalloc.get_traced_memory()
    print(f"Encryption - Current: {current / 1024:.2f} KB, Peak: {peak / 1024:.2f} KB")

    _ = decrypt(cipher, priv_key)
    current, peak = tracemalloc.get_traced_memory()
    print(f"Decryption - Current: {current / 1024:.2f} KB, Peak: {peak / 1024:.2f} KB")
    tracemalloc.stop()

# --- NETWORK TEST ---

def network(message: str, bits: int = 2048):
    print("Running RSA network test...")
    pub_key, priv_key = generate_keys(bits)
    cipher = encrypt(message, pub_key)

    def server():
        s = socket.socket()
        s.bind(("localhost", 9996))
        s.listen(1)
        conn, _ = s.accept()
        data = conn.recv(65536)
        received_cipher = int(data.decode())
        conn.close()
        s.close()

        _ = decrypt(received_cipher, priv_key)

    server_thread = threading.Thread(target=server)
    server_thread.start()

    start = timeit.default_timer()
    client_sock = socket.socket()
    client_sock.connect(("localhost", 9996))
    client_sock.send(str(cipher).encode())
    client_sock.close()
    server_thread.join()
    end = timeit.default_timer()

    print(f"Network + RSA decrypt latency: {end - start:.6f} sec")

# --- MAIN ---

def main():
    test_message = "Benchmarking RSA performance with 2048-bit keys"
    bits = 2048  # Use 4096 for stronger security, but 2048 is faster for testing

    print(f"\n--- RSA Test Suite (key size: {bits}) ---\n")
    speed(test_message, bits)
    print()
    memory(test_message, bits)
    print()
    network(test_message, bits)


if __name__ == "__main__":
    main()