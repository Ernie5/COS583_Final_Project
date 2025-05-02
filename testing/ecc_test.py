"""
NIST P-256 (ECDSA) benchmark
Depends on ecc.py that exposes:
    ECC_P256()
        .sign(msg_bytes)           -> bytes (DER-encoded sig)
        .verify(msg_bytes, sig)    -> bool
        .public_key                VerifyingKey
"""
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

from ecc import ECC_P256

# ---------------------------------------------------------------
# SPEED TEST
# ---------------------------------------------------------------
def speed(message: bytes, loops: int = 100) -> None:
    print("▶ SPEED")
    ecc = ECC_P256()

    sign_avg = timeit.timeit(lambda: ecc.sign(message), number=loops)
    sig = ecc.sign(message)
    ver_avg = timeit.timeit(lambda: ecc.verify(message, sig), number=loops)

    print(f"  {loops:,} signs   → {sign_avg:.3f}s "
          f"({sign_avg/loops:.6f}s each)")
    print(f"  {loops:,} verifies→ {ver_avg:.3f}s "
          f"({ver_avg/loops:.6f}s each)")


# ---------------------------------------------------------------
# MEMORY TEST
# ---------------------------------------------------------------
def memory(message: bytes) -> None:
    print("\n▶ MEMORY (tracemalloc)")
    tracemalloc.start()
    ecc = ECC_P256()

    sig = ecc.sign(message)
    curr, peak = tracemalloc.get_traced_memory()
    print(f"  sign      → current {curr/1024:7.2f} KB   peak {peak/1024:7.2f} KB")

    _ = ecc.verify(message, sig)
    curr, peak = tracemalloc.get_traced_memory()
    print(f"  verify    → current {curr/1024:7.2f} KB   peak {peak/1024:7.2f} KB")
    tracemalloc.stop()


# ---------------------------------------------------------------
# NETWORK + VERIFY TEST
# ---------------------------------------------------------------
def network(message: bytes) -> None:
    print("\n▶ NETWORK (localhost socket)")
    ecc = ECC_P256()
    signature = ecc.sign(message)
    payload = message + b'||' + signature
    payload_len = len(payload)

    # -------- server task (verifies after receive) --------------
    def server() -> None:
        with socket.socket() as srv:
            srv.bind(("localhost", 9_997))
            srv.listen(1)
            conn, _ = srv.accept()
            with conn:
                data = conn.recv(payload_len)
                msg, sig = data.split(b'||', 1)
                verifier = ECC_P256()
                verifier.public_key = ecc.public_key   # share pubkey
                _ = verifier.verify(msg, sig)

    srv_thread = threading.Thread(target=server, daemon=True)
    srv_thread.start()

    # -------- timed client send ---------------------------------
    start = time.perf_counter()
    with socket.socket() as cli:
        cli.connect(("localhost", 9_997))
        cli.sendall(payload)
    srv_thread.join()
    elapsed = time.perf_counter() - start

    print(f"  sent {payload_len} B in {elapsed:.6f}s  "
          f"({payload_len/elapsed/1024:.2f} KB/s incl. server verify)")


# ---------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------
def main() -> None:
    msg = b"Testing ECC performance metrics with NIST P-256."
    print("\n=== ECC-P256 Test Suite ===\n")
    speed(msg)
    memory(msg)
    network(msg)


if __name__ == "__main__":
    main()
