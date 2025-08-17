# iso8583_tcp.py
import os, socket, base64
from datetime import datetime

# Simple placeholder MAC key (hex). Replace with your HSM or derived session key.
MAC_HEX_KEY = os.getenv("MAC_HEX_KEY", "00112233445566778899AABBCCDDEEFF")

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

class ISO8583:
    """
    Minimal packer stub (for your acquirer spec you’ll replace this with real field packing).
    For now we just assemble a debug string -> bytes to make TCP exchange and logging work.
    """
    def __init__(self, mac_hex_key: str):
        self.key = mac_hex_key

    def pack(self, mti: str, fields: dict[int, str]) -> bytes:
        # Very simple line-based wireframe: "MTI|DE=VALUE;DE=VALUE;...|TS=YYYYmmddHHMMSS"
        pairs = ";".join([f"{k}={fields[k]}" for k in sorted(fields.keys())])
        line = f"{mti}|{pairs}|TS={datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        return line.encode("utf-8")

def iso_send_tcp(msg: bytes) -> bytes:
    """
    If ISO_HOST/ISO_PORT are set, will open TCP and send/recv.
    Otherwise returns a local ACK message so your flow is end-to-end functional.
    """
    host = os.getenv("ISO_HOST")
    port = int(os.getenv("ISO_PORT", "0")) if os.getenv("ISO_PORT") else None

    if host and port:
        with socket.create_connection((host, port), timeout=10) as s:
            s.sendall(msg)
            # naive single-recv; adjust to your wire protocol framing
            data = s.recv(4096)
            if not data:
                raise RuntimeError("No data received from ISO8583 host")
            return data

    # Local fallback (no external 3rd party): deduce response MTI by adding 10
    try:
        mti = msg.decode("utf-8").split("|", 1)[0]
    except Exception:
        mti = "0210"
    # return "ACK:<MTI>"
    if mti == "0200":
        resp = "0210|DE39=00;NOTE=LocalAuthOK"
    elif mti == "0500":
        resp = "0510|DE39=00;NOTE=LocalSettleOK"
    else:
        resp = "0210|DE39=00;NOTE=LocalAck"
    return resp.encode("utf-8")
