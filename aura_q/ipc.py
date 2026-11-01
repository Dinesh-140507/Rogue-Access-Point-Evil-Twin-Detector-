"""Step 6: CRC-framed Linux -> MCU message (PDF section 4.4).
[SOF 0xAA | VER 1B | TYPE 1B | SEQ 2B | LEN 1B | PAYLOAD 0-32B | CRC16 2B]   CRC covers VER..PAYLOAD."""
import struct

SOF, VER = 0xAA, 1
T_HEARTBEAT, T_STATUS, T_ALERT = 0x01, 0x02, 0x03
VALID_TYPES = {T_HEARTBEAT, T_STATUS, T_ALERT}
MAX_PAYLOAD = 32


def crc16_ccitt(data, crc=0xFFFF):
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def build_frame(msg_type, seq, payload=b""):
    assert len(payload) <= MAX_PAYLOAD
    body = struct.pack(">BBHB", VER, msg_type, seq & 0xFFFF, len(payload)) + payload
    return bytes([SOF]) + body + struct.pack(">H", crc16_ccitt(body))


def parse_frame(raw):
    """Return (ok, reason, msg). Mirrors what the STM32 firmware must check."""
    if len(raw) < 8:
        return False, "too_short", None
    if raw[0] != SOF:
        return False, "bad_sof", None
    ver, mtype, seq, plen = struct.unpack(">BBHB", raw[1:6])
    if ver != VER:
        return False, "bad_version", None
    if plen > MAX_PAYLOAD:
        return False, "oversized", None
    if len(raw) != 8 + plen:
        return False, "bad_length", None
    if mtype not in VALID_TYPES:
        return False, "unknown_type", None
    if crc16_ccitt(raw[1:-2]) != struct.unpack(">H", raw[-2:])[0]:
        return False, "bad_crc", None
    return True, "ok", dict(type=mtype, seq=seq, payload=raw[6:6 + plen])


def seq_newer(a, b):
    return 1 <= ((a - b) & 0xFFFF) <= 0x7FFF


class Sender:
    """Linux side (ipc_service.py): owns the sequence counter."""
    def __init__(self):
        self.seq = 0

    def frame(self, mtype, payload=b""):
        self.seq = (self.seq + 1) & 0xFFFF
        return build_frame(mtype, self.seq, payload)
