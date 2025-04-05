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

from dh import DiffieHellman, generate_large_prime

# --- SPEED TEST ---

def speed(key_size, generator):
    print("Running DH speed test...")
    prime = generate_large_prime(key_size)
    
    enc_time = timeit.timeit(lambda: DiffieHellman(generator, prime, key_size), number=100)
    alice = DiffieHellman(generator, prime, key_size)
    bob = DiffieHellman(generator, prime, key_size)
    dec_time = timeit.timeit(lambda: alice.compute_shared_secret(bob.public_key), number=100)
    
    print(f"Avg key generation time: {enc_time/100:.6f} sec")
    print(f"Avg shared secret compute time: {dec_time/100:.6f} sec")

# --- MEMORY TEST ---

def memory(key_size, generator):
    print("Running DH memory test...")
    prime = generate_large_prime(key_size)
    
    tracemalloc.start()
    alice = DiffieHellman(generator, prime, key_size)
    bob = DiffieHellman(generator, prime, key_size)
    current, peak = tracemalloc.get_traced_memory()
    print(f"Key generation - Current: {current / 1024:.2f} KB, Peak: {peak / 1024:.2f} KB")
    
    _ = alice.compute_shared_secret(bob.public_key)
    current, peak = tracemalloc.get_traced_memory()
    print(f"Shared secret - Current: {current / 1024:.2f} KB, Peak: {peak / 1024:.2f} KB")
    tracemalloc.stop()

# --- NETWORK TEST ---

def network(key_size, generator):
    print("Running DH network test...")
    prime = generate_large_prime(key_size)
    alice = DiffieHellman(generator, prime, key_size)
    
    def server():
        s = socket.socket()
        s.bind(("localhost", 9998))
        s.listen(1)
        conn, _ = s.accept()
        data = conn.recv(4096)
        bob_public = int(data.decode())
        conn.close()
        s.close()

        bob = DiffieHellman(generator, prime, key_size)
        _ = bob.compute_shared_secret(bob_public)

    server_thread = threading.Thread(target=server)
    server_thread.start()

    start = timeit.default_timer()
    client_sock = socket.socket()
    client_sock.connect(("localhost", 9998))
    client_sock.send(str(alice.public_key).encode())
    client_sock.close()
    server_thread.join()
    end = timeit.default_timer()

    print(f"Network + DH compute latency: {end - start:.6f} sec")

# --- MAIN ---

def main():
    key_size = 512  # Strong enough for demo
    generator = 2

    print(f"\n--- Diffie-Hellman Test Suite (key size: {key_size}) ---\n")
    speed(key_size, generator)
    print()
    memory(key_size, generator)
    print()
    network(key_size, generator)

if __name__ == "__main__":
    main()
