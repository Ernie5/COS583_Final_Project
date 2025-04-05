import timeit
import tracemalloc
import socket
import threading
import sys
import os

# Setup import path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(project_root, 'ClassicalCryptography'))

from ecc import ECC_P256

# --- SPEED TEST ---

def speed(message: bytes):
    print("Running ECC speed test...")
    ecc = ECC_P256()

    sign_time = timeit.timeit(lambda: ecc.sign(message), number=100)
    signature = ecc.sign(message)
    verify_time = timeit.timeit(lambda: ecc.verify(message, signature), number=100)

    print(f"Avg signing time: {sign_time / 100:.6f} sec")
    print(f"Avg verification time: {verify_time / 100:.6f} sec")

# --- MEMORY TEST ---

def memory(message: bytes):
    print("Running ECC memory test...")
    tracemalloc.start()
    ecc = ECC_P256()
    signature = ecc.sign(message)
    current, peak = tracemalloc.get_traced_memory()
    print(f"Signing - Current: {current / 1024:.2f} KB, Peak: {peak / 1024:.2f} KB")

    _ = ecc.verify(message, signature)
    current, peak = tracemalloc.get_traced_memory()
    print(f"Verification - Current: {current / 1024:.2f} KB, Peak: {peak / 1024:.2f} KB")
    tracemalloc.stop()

# --- NETWORK TEST ---

def network(message: bytes):
    print("Running ECC network test...")
    ecc = ECC_P256()
    signature = ecc.sign(message)

    def server():
        s = socket.socket()
        s.bind(("localhost", 9997))
        s.listen(1)
        conn, _ = s.accept()
        data = conn.recv(4096)
        conn.close()
        s.close()

        # Extract message and signature
        raw = data.split(b'||')
        msg, sig = raw[0], raw[1]
        server_ecc = ECC_P256()
        server_ecc.public_key = ecc.public_key  # share public key for verification
        _ = server_ecc.verify(msg, sig)

    server_thread = threading.Thread(target=server)
    server_thread.start()

    start = timeit.default_timer()
    client_sock = socket.socket()
    client_sock.connect(("localhost", 9997))
    client_sock.send(message + b'||' + signature)
    client_sock.close()
    server_thread.join()
    end = timeit.default_timer()

    print(f"Network + ECC verify latency: {end - start:.6f} sec")

# --- MAIN ---

def main():
    test_message = b"Testing ECC performance metrics with NIST P-256."
    print("\n--- ECC P-256 Test Suite ---\n")
    speed(test_message)
    print()
    memory(test_message)
    print()
    network(test_message)


if __name__ == "__main__":
    main()