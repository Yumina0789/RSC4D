"""Byte-level diff between the recorded recording and the rs-c4d response.

Both frames are 308 bytes and hold two PDUs (bind acknowledgement, then the
KMS response). The comparison therefore reduces to the response stub of each
side: every byte must agree except inside the ePID (chosen from the KMD
template here, randomised at startup by the recorded) and inside the CMAC,
which covers the ePID.
"""

import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from crosscheck_v4 import CASES, PORT, SERVER, stub_of, read_response

SERVER_PORT = PORT + 2
PID_OFFSET = 20
CMAC_SIZE = 16

def main():
    request = (CASES / "c1-c2s.bin").read_bytes()
    recorded_frame = (CASES / "c1-s2c.bin").read_bytes()
    recorded = stub_of(recorded_frame, 2)

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
    actual = stub_of(actual_frame, 2)

    print(f"response stub: rs-c4d={len(actual)} recorded={len(recorded)}")
    if len(actual) != len(recorded):
        print("length mismatch")
        return 1

    pid_size = struct.unpack_from("<I", recorded, 16)[0]
    pid_end = PID_OFFSET + pid_size
    mac_start = len(recorded) - CMAC_SIZE
    print(f"PIDSize={pid_size}  ePID field=[{PID_OFFSET},{pid_end})  CMAC=[{mac_start},{len(recorded)})")
    print(f"recorded ePID: {recorded[PID_OFFSET:pid_end].decode('utf-16-le', 'replace').rstrip(chr(0))}")
    print(f"rs-c4d    ePID: {actual[PID_OFFSET:pid_end].decode('utf-16-le', 'replace').rstrip(chr(0))}")

    differing = [index for index in range(len(recorded)) if actual[index] != recorded[index]]
    outside = [index for index in differing if not (PID_OFFSET <= index < pid_end or index >= mac_start)]
    print()
    print(f"differing bytes: {len(differing)}")
    if differing:
        ranges = []
        start = previous = differing[0]
        for index in differing[1:]:
            if index != previous + 1:
                ranges.append((start, previous))
                start = index
            previous = index
        ranges.append((start, previous))
        print("ranges: " + ", ".join(f"[{a},{b}]" for a, b in ranges))
    print(f"differences outside the ePID and CMAC fields: {len(outside)}"
          + (f" -> {outside}" if outside else " (none)"))
    same_prefix = 0
    while same_prefix < len(recorded) and actual[same_prefix] == recorded[same_prefix]:
        same_prefix += 1
    print(f"identical prefix: {same_prefix} bytes")
    return 0 if not outside else 1

if __name__ == "__main__":
    sys.exit(main())
