import time
import timeit
import tracemalloc
import socket
import threading
import sys
import os

# ---------------------------------------------------------------
# local package import
# ---------------------------------------------------------------
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(project_root, 'ClassicalCryptography'))

from rsa import generate_keys, encrypt, decrypt

# ---------------------------------------------------------------
# SPEED TEST
# ---------------------------------------------------------------
def speed(message: str, bits: int, loops: int = 100) -> None:
    print("▶ SPEED")
    keygen_t = timeit.timeit(lambda: generate_keys(bits), number=1)
    pub, priv = generate_keys(bits)

    enc_avg = timeit.timeit(lambda: encrypt(message, pub), number=loops)
    sample_ct = encrypt(message, pub)
    dec_avg = timeit.timeit(lambda: decrypt(sample_ct, priv), number=loops)

    print(f"  key-pair generation : {keygen_t:.3f}s")
    print(f"  {loops:,} encrypt   → {enc_avg:.3f}s "
          f"({enc_avg/loops:.6f}s each)")
    print(f"  {loops:,} decrypt   → {dec_avg:.3f}s "
          f"({dec_avg/loops:.6f}s each)")

# ---------------------------------------------------------------
# MEMORY TEST
# ---------------------------------------------------------------
def memory(message: str, bits: int) -> None:
    print("\n▶ MEMORY (tracemalloc)")
    tracemalloc.start()

    pub, priv = generate_keys(bits)
    _ = encrypt(message, pub)
    curr, peak = tracemalloc.get_traced_memory()
    print(f"  encrypt  → current {curr/1024:7.2f} KB   peak {peak/1024:7.2f} KB")

    ct = encrypt(message, pub)
    _ = decrypt(ct, priv)
    curr, peak = tracemalloc.get_traced_memory()
    print(f"  decrypt  → current {curr/1024:7.2f} KB   peak {peak/1024:7.2f} KB")
    tracemalloc.stop()

# ---------------------------------------------------------------
# NETWORK + DECRYPT TEST
# ---------------------------------------------------------------
def network(message: str, bits: int) -> None:
    print("\n▶ NETWORK (localhost socket)")
    pub, priv = generate_keys(bits)
    ct_bytes = encrypt(message, pub)
    payload_len = len(ct_bytes)

    # -------- server (decrypts after receive) --------------------
    def server() -> None:
        with socket.socket() as srv:
            srv.bind(("localhost", 9_996))
            srv.listen(1)
            conn, _ = srv.accept()
            with conn:
                cipher = conn.recv(payload_len)
                _ = decrypt(cipher, priv)

    srv_thread = threading.Thread(target=server, daemon=True)
    srv_thread.start()

    # -------- timed client send ---------------------------------
    start = time.perf_counter()
    with socket.socket() as cli:
        cli.connect(("localhost", 9_996))
        cli.sendall(ct_bytes)
    srv_thread.join()
    elapsed = time.perf_counter() - start

    print(f"  sent {payload_len} B in {elapsed:.6f}s  "
          f"({payload_len/elapsed/1024:.2f} KB/s incl. server decrypt)")

# ---------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------
def main() -> None:
    bits = 4096
    msg  = "Benchmarking RSA performance with 4096-bit keys"

    print(f"\n=== RSA Test Suite  (modulus: {bits} bits) ===\n")
    speed(msg, bits)
    memory(msg, bits)
    network(msg, bits)

if __name__ == "__main__":
    main()
