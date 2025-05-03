import time
import timeit
import tracemalloc
import socket
import threading
import sys
import os

# ------------------------------------------------------------------
# Local package import
# ------------------------------------------------------------------
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(project_root, 'ClassicalCryptography'))

from dh import DiffieHellman, generate_large_prime

# ------------------------------------------------------------------
# SPEED TEST
# ------------------------------------------------------------------
def speed(bits: int, g: int, loops: int = 100) -> None:
    print("▶ SPEED")
    p = generate_large_prime(bits)

    # key-pair generation
    gen_avg = timeit.timeit(lambda: DiffieHellman(g, p, bits),
                            number=loops)

    # shared-secret computation
    alice = DiffieHellman(g, p, bits)
    bob   = DiffieHellman(g, p, bits)
    ss_avg = timeit.timeit(lambda: alice.compute_shared_secret(bob.public_key),
                           number=loops)

    print(f"  {loops:,} keypair inits   →  {gen_avg:.3f}s "
          f"({gen_avg/loops:.6f}s each)")
    print(f"  {loops:,} shared-secrets  →  {ss_avg:.3f}s "
          f"({ss_avg/loops:.6f}s each)")

# ------------------------------------------------------------------
# MEMORY TEST
# ------------------------------------------------------------------
def memory(bits: int, g: int) -> None:
    print("\n▶ MEMORY (tracemalloc)")
    p = generate_large_prime(bits)

    tracemalloc.start()
    alice = DiffieHellman(g, p, bits)
    bob   = DiffieHellman(g, p, bits)
    curr, peak = tracemalloc.get_traced_memory()
    print(f"  keypair gen  → current {curr/1024:7.2f} KB   "
          f"peak {peak/1024:7.2f} KB")

    _ = alice.compute_shared_secret(bob.public_key)
    curr, peak = tracemalloc.get_traced_memory()
    print(f"  shared secret→ current {curr/1024:7.2f} KB   "
          f"peak {peak/1024:7.2f} KB")
    tracemalloc.stop()

# ------------------------------------------------------------------
# NETWORK TEST
# ------------------------------------------------------------------
def network(bits: int, g: int) -> None:
    print("\n▶ NETWORK (localhost socket)")
    p = generate_large_prime(bits)
    alice = DiffieHellman(g, p, bits)
    pk_bytes = str(alice.public_key).encode()
    payload_len = len(pk_bytes)

    # ------------ server task --------------------------------------
    def server() -> None:
        with socket.socket() as srv:
            srv.bind(("localhost", 9_998))
            srv.listen(1)
            conn, _ = srv.accept()
            with conn:
                bob_pk = int(conn.recv(payload_len).decode())
                bob = DiffieHellman(g, p, bits)
                _ = bob.compute_shared_secret(bob_pk)

    # ------------ timed client/server ------------------------------
    srv_thread = threading.Thread(target=server, daemon=True)
    srv_thread.start()

    start = time.perf_counter()
    with socket.socket() as cli:
        cli.connect(("localhost", 9_998))
        cli.sendall(pk_bytes)
    srv_thread.join()
    elapsed = time.perf_counter() - start

    print(f"  sent {payload_len:,} B in {elapsed:.6f}s  "
          f"({payload_len/elapsed/1024:.2f} KB/s, incl. server DH)")

# ------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------
def main() -> None:
    bits, g = 512, 2

    print(f"\n=== Diffie-Hellman Test Suite  (prime bits: {bits}) ===\n")
    speed(bits, g)
    memory(bits, g)
    network(bits, g)

if __name__ == "__main__":
    main()
