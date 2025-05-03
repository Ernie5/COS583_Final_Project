import base64
import time
import timeit
import tracemalloc
import socket
import threading
import sys
import os

# -----------------  local package import  -----------------
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(project_root, 'ClassicalCryptography'))

from aes import generate_printable_key, encrypt, decrypt

# -----------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------
def _prep_key() -> tuple[str, bytes]:
    """Return (printable_key_str, key_bytes) ready for AES.new()."""
    printable = generate_printable_key()           # 32 ASCII chars
    return printable, printable.encode()           # ASCII -> bytes

# -----------------------------------------------------------------
# SPEED TEST
# -----------------------------------------------------------------
def speed(plaintext: str, key: bytes, iterations: int = 1_000) -> None:
    print("▶ SPEED")
    enc_avg = timeit.timeit(lambda: encrypt(plaintext, key), number=iterations)
    sample_cipher = encrypt(plaintext, key)        # keep a sample for decrypt loop
    dec_avg = timeit.timeit(lambda: decrypt(sample_cipher, key), number=iterations)

    print(f"  {iterations:,}   encrypt calls → {enc_avg:.3f}s  "
          f"({enc_avg/iterations:.6f}s each)")
    print(f"  {iterations:,}   decrypt calls → {dec_avg:.3f}s  "
          f"({dec_avg/iterations:.6f}s each)")

# -----------------------------------------------------------------
# MEMORY TEST
# -----------------------------------------------------------------
def memory(plaintext: str, key: bytes) -> None:
    print("\n▶ MEMORY (tracemalloc)")
    tracemalloc.start()

    # encryption snapshot
    _ = encrypt(plaintext, key)
    curr, peak = tracemalloc.get_traced_memory()
    print(f"  encrypt → current {curr/1024:7.2f} KB   peak {peak/1024:7.2f} KB")

    # decryption snapshot (using same ciphertext size)
    ciphertext = encrypt(plaintext, key)
    _ = decrypt(ciphertext, key)
    curr, peak = tracemalloc.get_traced_memory()
    print(f"  decrypt → current {curr/1024:7.2f} KB   peak {peak/1024:7.2f} KB")

    tracemalloc.stop()

# -----------------------------------------------------------------
# NETWORK TEST
# -----------------------------------------------------------------
def network(plaintext: str, key: bytes) -> None:
    print("\n▶ NETWORK (localhost socket)")

    ciphertext = encrypt(plaintext, key).encode()     # send bytes
    payload_len = len(ciphertext)

    # --- server task ------------------------------------------------
    def server() -> None:
        with socket.socket() as srv:
            srv.bind(("localhost", 9_999))
            srv.listen(1)
            conn, _ = srv.accept()
            with conn:
                _ = conn.recv(payload_len)

    # --- run timed client/server ------------------------------------
    srv_thread = threading.Thread(target=server, daemon=True)
    srv_thread.start()

    start = time.perf_counter()
    with socket.socket() as cli:
        cli.connect(("localhost", 9_999))
        cli.sendall(ciphertext)
    srv_thread.join()
    elapsed = time.perf_counter() - start

    print(f"  sent {payload_len:,} B in {elapsed:.6f}s  "
          f"({payload_len/elapsed/1024:.2f} KB/s)")

# -----------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------
def main() -> None:
    printable_key, key = _prep_key()
    msg = "Hello, AES-256! " * 100   # ~1.6 KB message

    print(f"Printable key   : {printable_key}")
    print(f"Key (Base64)    : {base64.b64encode(key).decode()}\n")

    speed(msg, key)
    memory(msg, key)
    network(msg, key)

if __name__ == "__main__":
    main()
