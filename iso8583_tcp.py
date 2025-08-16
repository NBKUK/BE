import os, hmac, hashlib, socket, base64
from datetime import datetime
from typing import Dict, Any

ISO_TCP_HOST = os.environ.get("ISO_TCP_HOST", "127.0.0.1")
ISO_TCP_PORT = int(os.environ.get("ISO_TCP_PORT", "5000"))
MAC_HEX_KEY = bytes.fromhex(os.environ.get("MAC_HEX_KEY", "00112233445566778899AABBCCDDEEFF"))

class ISO8583:
    def __init__(self, mac_key: bytes):
        self.mac_key = mac_key

    # --- field encoders ---
    def _llvar(self, s: str) -> bytes:
        b = s.encode()
        return f"{len(b):02d}".encode() + b

    def _lllvar(self, s: str) -> bytes:
        b = s.encode()
        return f"{len(b):03d}".encode() + b

    def _bitmap(self, fields: Dict[int, bytes]) -> bytes:
        # primary bitmap only (1-64)
        bits = [0] * 64
        for f in fields:
            if 1 <= f <= 64:
                bits[f - 1] = 1
            else:
                raise ValueError("Secondary bitmap not implemented in this minimal packer")
        out = bytearray()
        b = 0
        for i, bit in enumerate(bits):
            b = (b << 1) | bit
            if (i + 1) % 8 == 0:
                out.extend(f"{b:02X}".encode())
                b = 0
        return bytes(out)

    def compute_mac(self, msg_wo_mac: bytes) -> bytes:
        hm = hmac.new(self.mac_key, msg_wo_mac, hashlib.sha256).hexdigest().upper()
        return hm[:16].encode()  # 8 bytes hex-ASCII (typical DE64 style)

    def pack(self, mti: str, data: Dict[int, Any]) -> bytes:
        enc: Dict[int, bytes] = {}
        for de, v in sorted(data.items()):
            if v is None:
                continue
            if de in (2, 32):
                enc[de] = self._llvar(str(v))
            elif de in (60, 61, 63):
                enc[de] = self._lllvar(str(v))
            elif de == 64:
                enc[de] = b""  # placeholder
            else:
                enc[de] = str(v).encode()

        used_fields = sorted(k for k in enc.keys() if k != 64)
        bmp = self._bitmap({k: b"" for k in used_fields})

        body = mti.encode() + bmp
        for de in used_fields:
            body += enc[de]

        mac = self.compute_mac(body)
        body += mac  # DE64

        # 2-byte big-endian length prefix
        return len(body).to_bytes(2, "big") + body

def iso_send_tcp(payload: bytes, host: str = ISO_TCP_HOST, port: int = ISO_TCP_PORT, timeout: int = 20) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(payload)
        lp = s.recv(2)
        if len(lp) < 2:
            raise IOError("Short read on ISO8583 length prefix")
        ln = int.from_bytes(lp, "big")
        buf = b""
        while len(buf) < ln:
            chunk = s.recv(ln - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()

