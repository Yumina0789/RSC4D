"""Structural check of the v5 and v6 exchanges against the recorded recorded.

Their response bodies are encrypted with fresh random material each time, so a
byte comparison is impossible without injecting the recorded randomness.
What can be compared is the framing: PDU sizes, the stub header (whose first
DWORD is the payload length) and the clear leading bytes of the KMS response.
"""

import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from crosscheck_v4 import CASES, PORT, SERVER, stub_of, read_response

SERVER_PORT = PORT + 3
HEADER = 16

def pdus(frame):
    out = []
    start = 0
    while start + HEADER <= len(frame):
        ptype = frame[start + 2]
        fragment = struct.unpack_from("<H", frame, start + 8)[0]
        if fragment < HEADER or start + fragment > len(frame):
            break
        out.append((ptype, frame[start : start + fragment]))
        start += fragment
    return out

def replay(port, request):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as stream:
        stream.sendall(request)
        return read_response(stream)

def main():
    server = subprocess.Popen(
        [str(SERVER), "--listen", "127.0.0.1", "--port", str(SERVER_PORT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    failures = 0
    try:
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", SERVER_PORT), timeout=0.3):
                    break
            except OSError:
                time.sleep(0.1)
        for case in ("c2", "c3"):
            request = (CASES / f"{case}-c2s.bin").read_bytes()
            recorded = (CASES / f"{case}-s2c.bin").read_bytes()
            actual = replay(SERVER_PORT, request)
            print(f"=== {case}: rs-c4d {len(actual)} bytes, recorded {len(recorded)} bytes"
                  f" {'(same size)' if len(actual) == len(recorded) else '(SIZE MISMATCH)'}")
            for label, frame in (("recorded", recorded), ("rs-c4d", actual)):
                parts = pdus(frame)
                summary = ", ".join(
                    f"ptype={ptype} frag={len(pdu)}" for ptype, pdu in parts
                )
                print(f"    {label:<9} PDUs: {summary}")
                if len(parts) >= 2:
                    body = stub_of(frame, 2)
                    length = struct.unpack_from("<I", body, 0)[0]
                    print(f"    {'':<9} stub={len(body)} declared_payload={length}"
                          f" clear_head={body[12:20].hex()}")
                    recorded_body = stub_of(recorded, 2)
                    clean = body[:12] == recorded_body[:12]
                    print(f"    {'':<9} 12-byte stub header identical: {clean}")
                    if not clean or len(actual) != len(recorded):
                        failures += 1
    finally:
        server.kill()
        server.wait()
    return 1 if failures else 0

if __name__ == "__main__":
    sys.exit(main())
