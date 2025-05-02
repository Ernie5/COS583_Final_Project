"""
ML-KEM-1024 (Kyber-1024) benchmark                ────────────────
Needs:  pip install oqs
Measures:
  • key-pair generation
  • encapsulation / decapsulation (avg over LOOPS runs)
  • peak memory with tracemalloc
  • “network” latency (client sends ciphertext; server decaps)
"""
import time
import timeit
import tracemalloc
import socket
import threading

import oqs

ALG   = "ML-KEM-1024"
PORT  = 9_994              # unique port
LOOPS = 100                # encapsulation / decapsulation loops


# ------------------------------------------------------------------
# SPEED TEST
# ------------------------------------------------------------------
def speed(loops: int = LOOPS) -> None:
    print("▶ SPEED")
    with oqs.KeyEncapsulation(ALG) as server:
        keygen_t = timeit.timeit(server.generate_keypair, number=1)
        pub_key = server.generate_keypair()

        # Encapsulation (client side)
        with oqs.KeyEncapsulation(ALG) as client:
            enc_avg = timeit.timeit(lambda: client.encap_secret(pub_key),
                                    number=loops)
            ct, ss_enc = client.encap_secret(pub_key)   # sample cipher

        # Decapsulation (server side)
        dec_avg = timeit.timeit(lambda: server.decap_secret(ct),
                                number=loops)

    print(f"  key-pair generation : {keygen_t:.3f}s")
    print(f"  {loops:,} encaps    → {enc_avg:.3f}s "
          f"({enc_avg/loops:.6f}s each)")
    print(f"  {loops:,} decaps    → {dec_avg:.3f}s "
          f"({dec_avg/loops:.6f}s each)")


# ------------------------------------------------------------------
# MEMORY TEST
# ------------------------------------------------------------------
def memory() -> None:
    print("\n▶ MEMORY (tracemalloc)")
    tracemalloc.start()
    with oqs.KeyEncapsulation(ALG) as server:
        pk = server.generate_keypair()

        with oqs.KeyEncapsulation(ALG) as client:
            ct, ss_enc = client.encap_secret(pk)
        curr, peak = tracemalloc.get_traced_memory()
        print(f"  encaps     → current {curr/1024:7.2f} KB   "
              f"peak {peak/1024:7.2f} KB")

        _ = server.decap_secret(ct)
        curr, peak = tracemalloc.get_traced_memory()
        print(f"  decap      → current {curr/1024:7.2f} KB   "
              f"peak {peak/1024:7.2f} KB")
    tracemalloc.stop()


# ------------------------------------------------------------------
# NETWORK + DECAP TEST   (fixed)
# ------------------------------------------------------------------
def network() -> None:
    print("\n▶ NETWORK (localhost socket)")

    # ---- prepare server KEM and client ciphertext ---------------
    with oqs.KeyEncapsulation(ALG) as server_kem:
        pk = server_kem.generate_keypair()              # pub / sec keys live here

        with oqs.KeyEncapsulation(ALG) as client_kem:
            ct, ss_client = client_kem.encap_secret(pk) # client side

        payload      = ct                # only ciphertext travels
        payload_len  = len(payload)

        # ---- server thread: decapsulates with the SAME object ----
        def server_task() -> None:
            with socket.socket() as srv:
                srv.bind(("localhost", PORT))
                srv.listen(1)
                conn, _ = srv.accept()
                with conn:
                    ct_recv = conn.recv(payload_len)
                    _ = server_kem.decap_secret(ct_recv)   # uses server’s secret key

        srv_thread = threading.Thread(target=server_task, daemon=True)
        srv_thread.start()

        # ---- timed client send ----------------------------------
        start = time.perf_counter()
        with socket.socket() as cli:
            cli.connect(("localhost", PORT))
            cli.sendall(payload)
        srv_thread.join()
        elapsed = time.perf_counter() - start

    print(f"  sent {payload_len:,} B in {elapsed:.6f}s  "
          f"({payload_len/elapsed/1024:.2f} KB/s incl. server decap)")



# ------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------
def main() -> None:
    print(f"\n=== ML-KEM-1024 Test Suite ===\n")
    speed()
    memory()
    network()


if __name__ == "__main__":
    main()
