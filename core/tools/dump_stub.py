"""Dump the located RESPONSE stubs of the recorded recording and of rs-c4d."""

import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from crosscheck_v4 import CASES, PORT, SERVER, stub_of, read_response

SERVER_PORT = PORT + 1

def dump(label, frame, body):
    print(f"--- {label}: PDU {len(frame)} bytes, stub {len(body)} bytes")
    print(f"    PDU header: {frame[:16].hex()}")
    print(f"    stub head : {body[:32].hex()}")

def main():
    request = (CASES / "c1-c2s.bin").read_bytes()
    recorded_frame = (CASES / "c1-s2c.bin").read_bytes()
    recorded_body = stub_of(recorded_frame, 2)

    server = subprocess.Popen(
        [str(SERVER), "--listen", "127.0.0.1", "--port", str(SERVER_PORT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", SERVER_PORT), timeout=0.3):
                    break
            except OSError:
                time.sleep(0.1)
        with socket.create_connection(("127.0.0.1", SERVER_PORT), timeout=5) as stream:
            stream.sendall(request)
            actual_frame = read_response(stream)
    finally:
        server.kill()
        server.wait()

    print("request head:", request[:16].hex())
    dump("recorded", recorded_frame, recorded_body)
    print(f"--- rs-c4d: {len(actual_frame)} bytes")
    for offset in range(0, min(len(actual_frame), 64), 16):
        print(f"    {offset:04x}  {actual_frame[offset:offset + 16].hex()}")
    for packet_type in (0, 2, 12):
        try:
            body = stub_of(actual_frame, packet_type)
        except SystemExit as error:
            print(f"    ptype {packet_type}: {error}")
            continue
        dump(f"rs-c4d ptype={packet_type}", actual_frame, body)

if __name__ == "__main__":
    main()
