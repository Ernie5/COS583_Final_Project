import base64
import timeit
import tracemalloc
import socket
import threading
import sys
import os


# Get the absolute path to the root 'project' directory
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Add 'utils' to the Python path
sys.path.append(os.path.join(project_root, 'ClassicalCryptography'))

from aes import generate_key, encrypt, decrypt


# --- SPEED TEST ---

def speed(plaintext, key, iterations=1000):
    print("Running AES speed test...")
    enc_time = timeit.timeit(lambda: encrypt(plaintext, key), number=iterations)
    encrypted_text = encrypt(plaintext, key)
    dec_time = timeit.timeit(lambda: decrypt(encrypted_text, key), number=iterations)
    print(f"Average encryption time: {enc_time/iterations:.6f} sec")
    print(f"Average decryption time: {dec_time/iterations:.6f} sec")

# --- MEMORY TEST ---

def memory(plaintext, key):
    print("Running AES memory test...")
    tracemalloc.start()
    encrypted = encrypt(plaintext, key)
    current, peak = tracemalloc.get_traced_memory()
    print(f"Encryption - Current: {current / 1024:.2f} KB, Peak: {peak / 1024:.2f} KB")
    decrypted = decrypt(encrypted, key)
    current, peak = tracemalloc.get_traced_memory()
    print(f"Decryption - Current: {current / 1024:.2f} KB, Peak: {peak / 1024:.2f} KB")
    tracemalloc.stop()

# --- NETWORK TEST ---

def network(plaintext, key):
    print("Running AES network test...")

    encrypted_text = encrypt(plaintext, key)

    # Server function
    def server():
        s = socket.socket()
        s.bind(("localhost", 9999))
        s.listen(1)
        conn, addr = s.accept()
        data = conn.recv(4096)
        conn.close()
        s.close()

    # Client function
    def client():
        s = socket.socket()
        s.connect(("localhost", 9999))
        s.send(encrypted_text.encode())
        s.close()

    # Start server thread
    server_thread = threading.Thread(target=server)
    server_thread.start()

    # Measure client send time
    start = timeit.default_timer()
    client()
    server_thread.join()
    end = timeit.default_timer()

    print(f"Network transfer time (encrypted data): {end - start:.6f} sec")

# --- MAIN EXECUTION ---

def main():
    key = generate_key()
    plaintext = "Hello, AES-256! " * 100  # Bigger data for meaningful tests

    print(f"Generated Key (Base64): {base64.b64encode(key).decode()}")
    print()

    speed(plaintext, key)
    print()
    memory(plaintext, key)
    print()
    network(plaintext, key)

if __name__ == "__main__":
    main()
