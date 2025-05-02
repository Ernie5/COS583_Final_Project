"""
SPHINCS+ benchmark  (variant:  SPHINCS+-SHAKE-256s-simple)  ────────────────
Needs:  pip install oqs
Measures:
  • key-pair generation
  • signing / verification (avg over LOOPS runs)
  • peak memory with tracemalloc
  • “network” latency: client sends msg‖sig; server verifies
"""
import time
import timeit
import tracemalloc
import socket
import threading

import oqs

ALG   = "SPHINCS+-SHAKE-256s-simple"
PORT  = 9_993                # unique port – won’t clash with earlier tests
LOOPS = 50                   # fewer loops: SPHINCS+ signatures are heavy

# ------------------------------------------------------------------
# SPEED TEST
# ------------------------------------------------------------------
def speed(msg: bytes, loops: int = LOOPS) -> None:
    print("▶ SPEED")
    with oqs.Signature(ALG) as signer:
        keygen_t = timeit.timeit(signer.generate_keypair, number=1)
        pub_key = signer.generate_keypair()

        sign_avg = timeit.timeit(lambda: signer.sign(msg), number=loops)
        sample_sig = signer.sign(msg)

    with oqs.Signature(ALG) as verifier:
        verify_avg = timeit.timeit(
            lambda: verifier.verify(msg, sample_sig, pub_key),
            number=loops
        )

    print(f"  key-pair generation : {keygen_t:.3f}s")
    print(f"  {loops:,} signs     → {sign_avg:.3f}s "
          f"({sign_avg/loops:.6f}s each)")
    print(f"  {loops:,} verifies  → {verify_avg:.3f}s "
          f"({verify_avg/loops:.6f}s each)")


# ------------------------------------------------------------------
# MEMORY TEST
# ------------------------------------------------------------------
def memory(msg: bytes) -> None:
    print("\n▶ MEMORY (tracemalloc)")
    tracemalloc.start()
    with oqs.Signature(ALG) as signer:
        pub_key = signer.generate_keypair()
        sig = signer.sign(msg)
        curr, peak = tracemalloc.get_traced_memory()
        print(f"  sign       → current {curr/1024:7.2f} KB   "
              f"peak {peak/1024:7.2f} KB")

    with oqs.Signature(ALG) as verifier:
        _ = verifier.verify(msg, sig, pub_key)
        curr, peak = tracemalloc.get_traced_memory()
        print(f"  verify     → current {curr/1024:7.2f} KB   "
              f"peak {peak/1024:7.2f} KB")
    tracemalloc.stop()


# ------------------------------------------------------------------
# NETWORK + VERIFY TEST
# ------------------------------------------------------------------
def network(msg: bytes) -> None:
    print("\n▶ NETWORK (localhost socket)")
    with oqs.Signature(ALG) as signer:
        pub_key = signer.generate_keypair()
        sig = signer.sign(msg)

    payload = msg + b'||' + sig
    payload_len = len(payload)

    # ---------- server task ---------------------------------------
    def server() -> None:
        with socket.socket() as srv:
            srv.bind(("localhost", PORT))
            srv.listen(1)
            conn, _ = srv.accept()
            with conn:
                data = conn.recv(payload_len)
                m, s = data.split(b'||', 1)
                with oqs.Signature(ALG) as ver:
                    _ = ver.verify(m, s, pub_key)

    srv_thread = threading.Thread(target=server, daemon=True)
    srv_thread.start()

    # ---------- timed client send ---------------------------------
    start = time.perf_counter()
    with socket.socket() as cli:
        cli.connect(("localhost", PORT))
        cli.sendall(payload)
    srv_thread.join()
    elapsed = time.perf_counter() - start

    print(f"  sent {payload_len:,} B in {elapsed:.6f}s  "
          f"({payload_len/elapsed/1024:.2f} KB/s incl. server verify)")


# ------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------
def main() -> None:
    msg = b"Post-Quantum Cryptography is the future!"
    print(f"\n=== SPHINCS+ Test Suite  ({ALG}) ===\n")
    speed(msg)
    memory(msg)
    network(msg)


if __name__ == "__main__":
    main()
