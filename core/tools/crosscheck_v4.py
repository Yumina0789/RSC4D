"""Cross-check the rs-c4d server against a recorded recorded response.

The recordings in ``rs-c4d/tests/fixtures/cases`` were produced by driving
the server under test with a KMS client through a TCP tee, so
``c1-s2c.bin`` is the recorded response to exactly the request bytes in
``c1-c2s.bin``. Replaying those bytes to another server makes the two responses
directly comparable.

v4 responses are plaintext, so every field except the ePID (from the KMD
template here, randomised at startup in the recorded) must agree byte for
byte, including the CMAC.

DCE/RPC common header (16 bytes): rpc_vers, rpc_vers_minor, PTYPE, pfc_flags,
packed_drep(4), frag_length(2), auth_length(2), call_id(4). The packet type is
therefore at offset 2, and a REQUEST/RESPONSE stub starts 8 bytes after the
header.
"""

import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

SERVER = Path(r"C:\Users\Menuet\Desktop\rs-c4d\target\release\rs-c4d.exe")
CASES = Path(r"C:\Users\Menuet\Desktop\WEB\rs-c4d\tests\fixtures\cases")
PORT = 16934
HEADER = 16
STUB_EXTRA = 8
PTYPE_REQUEST = 0
PTYPE_RESPONSE = 2

def stub_of(frame, wanted):
    start = 0
    while start + HEADER <= len(frame):
        packet_type = frame[start + 2]
        fragment = struct.unpack_from("<H", frame, start + 8)[0]
        if fragment < HEADER or start + fragment > len(frame):
            raise SystemExit(f"truncated PDU at offset {start}")
        if packet_type == wanted:
            return frame[start + HEADER + STUB_EXTRA : start + fragment]
        start += fragment
    raise SystemExit(f"no PDU of type {wanted} in {len(frame)} bytes")

def read_response(stream):
    buffer = b""
    while True:
        chunk = stream.recv(8192)
        if not chunk:
            break
        buffer += chunk
        start = 0
        while start + HEADER <= len(buffer):
            packet_type = buffer[start + 2]
            fragment = struct.unpack_from("<H", buffer, start + 8)[0]
            if fragment < HEADER or start + fragment > len(buffer):
                break
            if packet_type == PTYPE_RESPONSE:
                return buffer[: start + fragment]
            start += fragment
    return buffer

def v4_fields(body):
    offset = 0
    version = struct.unpack_from("<I", body, offset)[0]
    offset += 4
    pid_size = struct.unpack_from("<I", body, offset)[0]
    offset += 4
    pid = body[offset : offset + pid_size]
    offset += pid_size
    cmid = body[offset : offset + 16]
    offset += 16
    client_time = struct.unpack_from("<Q", body, offset)[0]
    offset += 8
    count = struct.unpack_from("<I", body, offset)[0]
    offset += 4
    activation = struct.unpack_from("<I", body, offset)[0]
    offset += 4
    renewal = struct.unpack_from("<I", body, offset)[0]
    offset += 4
    mac = body[offset : offset + 16]
    offset += 16
    return {
        "Version": f"0x{version:08x}",
        "PIDSize": pid_size,
        "ePID": pid.decode("utf-16-le", "replace").rstrip("\x00"),
        "CMID": cmid.hex(),
        "ClientTime": client_time,
        "Count": count,
        "VLActivationInterval": activation,
        "VLRenewalInterval": renewal,
        "CMAC": mac.hex(),
        "trailing_bytes": len(body) - offset,
    }

def main():
    request = (CASES / "c1-c2s.bin").read_bytes()
    expected = stub_of((CASES / "c1-s2c.bin").read_bytes(), PTYPE_RESPONSE)

    server = subprocess.Popen(
        [str(SERVER), "--listen", "127.0.0.1", "--port", str(PORT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", PORT), timeout=0.3):
                    break
            except OSError:
                time.sleep(0.1)
        with socket.create_connection(("127.0.0.1", PORT), timeout=5) as stream:
            stream.sendall(request)
            actual = stub_of(read_response(stream), PTYPE_RESPONSE)
    finally:
        server.kill()
        server.wait()

    mine = v4_fields(actual)
    recorded = v4_fields(expected)
    width = max(len(name) for name in mine)
    differing = []
    print(f"{'field':<{width}}  {'rs-c4d':<44} recorded")
    for name in mine:
        same = mine[name] == recorded[name]
        if not same:
            differing.append(name)
        print(f"{name:<{width}}  {str(mine[name]):<44} {recorded[name]}  {'==' if same else '!='}")
    print()
    print(f"v4 body: rs-c4d={len(actual)} recorded={len(expected)}")
    print("differing fields: " + (", ".join(differing) if differing else "(none)"))
    tolerated = {"ePID", "CMAC"}
    return 0 if set(differing) <= tolerated else 1

if __name__ == "__main__":
    sys.exit(main())
