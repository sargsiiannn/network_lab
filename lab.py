"""Traffic and capture checks for the four-node Linux test."""
import socket
import struct
import sys
from pathlib import Path

HOST = "10.55.0.2"
PORT = 9090
REQUEST = b"taglink-demo-west-61487" * 1024
RESPONSE = b"taglink-demo-east-38142" * 1024


def read_all(peer):
    blocks = []
    while block := peer.recv(16384):
        blocks.append(block)
    return b"".join(blocks)


def server():
    with socket.socket() as listener:
        listener.bind((HOST, PORT))
        listener.listen(1)
        print("Ready", flush=True)
        peer, _ = listener.accept()
        with peer:
            peer.settimeout(10)
            assert read_all(peer) == REQUEST
            peer.sendall(RESPONSE)


def client():
    with socket.create_connection((HOST, PORT), timeout=10) as peer:
        peer.sendall(REQUEST)
        peer.shutdown(socket.SHUT_WR)
        assert read_all(peer) == RESPONSE
    print("PASS bidirectional TCP payload across four nodes")


def packets(path):
    data = Path(path).read_bytes()
    assert data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")
    order = "<" if data[0] == 0xd4 else ">"
    assert struct.unpack_from(order + "I", data, 20)[0] & 0xffff == 1
    offset = 24
    while offset < len(data):
        captured = struct.unpack_from(order + "I", data, offset + 8)[0]
        frame = data[offset + 16:offset + 16 + captured]
        offset += 16 + captured
        assert frame[12:14] == b"\x08\x00" and frame[23] == 6
        size = int.from_bytes(frame[16:18], "big")
        ihl = (frame[14] & 15) * 4
        tcp = 14 + ihl
        thl = (frame[tcp + 12] >> 4) * 4
        header = bytearray(frame[:tcp + thl])
        header[16:18] = header[24:26] = header[tcp + 16:tcp + 18] = b"\0\0"
        yield bytes(header), frame[tcp + thl:14 + size]


def compare(lan, transit):
    plain = list(packets(lan))
    wire = list(packets(transit))
    known = {(h, len(p)) for h, p in plain}
    assert wire and known
    assert all((h, len(p) - 16) in known for h, p in wire)
    for marker in (REQUEST[:22], RESPONSE[:22]):
        assert any(marker in payload for _, payload in plain)
        assert all(marker not in payload for _, payload in wire)
    print("PASS original headers and exactly 16 added bytes per protected frame")


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "listen":
        server()
    elif mode == "connect":
        client()
    elif mode == "compare":
        compare(*sys.argv[2:])
    else:
        raise SystemExit("Unknown test mode")
