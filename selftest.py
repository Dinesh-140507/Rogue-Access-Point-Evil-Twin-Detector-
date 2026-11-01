"""Self-test for the whole laptop side. No hardware needed.

    python selftest.py

It checks:
  1. the ESP32 text-line parser and the frame builder (including a golden frame that the
     C firmware test also produces),
  2. the live path: simulated sessions are converted into the exact text lines the ESP32
     sends (including a clock that wraps around 2^32 microseconds), then fed through the
     parser, the baseline learner and the live engine,
  3. the expected verdicts: clean network -> no SUSPICIOUS; evil twin and rogue AP -> SUSPICIOUS
     shortly after the attack starts; sensor silence -> SYSTEM_FAULT.
"""
import os, sys, tempfile, zlib
import numpy as np
from config import *
import generator as G
import ipc
import baseline
import live_engine as LE
import sensor_link as SL

failures = []


def check(cond, msg):
    print(("PASS  " if cond else "FAIL  ") + msg)
    if not cond:
        failures.append(msg)


from demo_tools import sim_to_lines, BOOT_OFFSET


# ------------------------------------------------------------ 1. parser and frame builder
check(SL.parse_line("B|6|-52|1234|4294967000|A4:2B:8C:11:00:02|WPA2-Enterprise|123|IIITB-Campus\n")["ssid"]
      == "IIITB-Campus", "beacon line parses")
check(SL.parse_line("D|6|1000|a4:2b:8c:11:00:02")["bssid"] == "A4:2B:8C:11:00:02", "deauth line parses, MAC upper-cased")
check(SL.parse_line("S|5000|HEALTHY|0|2")["state"] == "HEALTHY", "status line parses")
check(SL.parse_line("B|6|-52|1234|bad") is None, "malformed line is rejected, not crashing")
check(ipc.build_frame(ipc.T_HEARTBEAT, 1).hex().upper() == "AA0101000100FED8",
      "heartbeat frame matches the golden bytes used by the C test")
check(SL.parse_line("B|6|-52|1234|1|A4:2B:8C:11:00:02|Open|1|x|extra") is None, "wrong field count rejected")

# ------------------------------------------------------------ 2. baseline learned from text lines
learn_link = SL.MemoryLink()
normal_learn = G.build("normal", 9001)[:2]
for line in sim_to_lines(*normal_learn):
    learn_link.ingest(line)
check(learn_link.esp_clock > 4200 + DURATION - 1 and learn_link.first_t is not None,
      "clock survives the 32-bit wrap (sensor time reaches the end of the session)")
t0 = learn_link.first_t
base, _ = LE.learn_baseline(LE.shifted(learn_link.beacons_since(t0), t0),
                            LE.shifted(learn_link.deauths_since(t0), t0), duration=DURATION)
check(len(base["aps"]) == len(G.TRUSTED),
      f"baseline learned all {len(G.TRUSTED)} trusted APs from text lines (got {len(base['aps'])})")
tmp_db = os.path.join(tempfile.mkdtemp(), "base.db")
baseline.save(base, tmp_db)
check(len(baseline.load(tmp_db)["aps"]) == len(base["aps"]), "baseline survives a SQLite save and load")


# ------------------------------------------------------------ 3. live engine verdicts
def run_session(kind, seed):
    """Feed one simulated session through the live engine, one 2-second step at a time."""
    streams, deauths, truth = G.build(kind, seed)
    lines = sim_to_lines(streams, deauths)
    link = SL.MemoryLink()
    link.status = {"state": "HEALTHY", "drops": 0, "rejects": 0}
    log = os.path.join(tempfile.mkdtemp(), "alerts.log")
    engine = LE.LiveEngine(link, base, ml=None, log_path=log, mode="rules")
    states, idx = [], 0
    for T in np.arange(LIVE_STEP_S, DURATION + 1e-9, LIVE_STEP_S):
        while idx < len(lines) and link.esp_clock <= BOOT_OFFSET + T:
            link.ingest(lines[idx]); idx += 1
        link.last_wall = __import__("time").monotonic()      # the sensor is alive in this test
        st = engine.step()
        states.append((BOOT_OFFSET + T, st["overall"], st["headline"]))   # absolute sensor time
    return states, truth


def first_suspicious(states):
    for T, overall, _ in states:
        if overall == "SUSPICIOUS":
            return T
    return None


clean_hits = 0
for seed in range(3):
    states, _ = run_session("normal", 7000 + seed)
    clean_hits += sum(1 for _, o, _ in states if o == "SUSPICIOUS")
check(clean_hits == 0, "clean network: no SUSPICIOUS verdict in 3 sessions of 120 s")

for kind in ["evil_twin", "rogue_ap"]:
    states, truth = run_session(kind, 7100)
    t_hit = first_suspicious(states)
    onset = BOOT_OFFSET + ATTACK_START
    ok = t_hit is not None and onset - 2.0 <= t_hit <= onset + 15   # no alarm before the attack, alarm soon after
    check(ok, f"{kind}: SUSPICIOUS from attack onset, within 15 s (no alarm before it) (first hit {None if t_hit is None else round(t_hit - onset, 1)} s after onset)")

states, _ = run_session("evil_twin", 7100)
check(any(o == "SYSTEM_FAULT" for _, o, _ in states) is False, "no false SYSTEM_FAULT while the sensor is streaming")

# sensor silence -> SYSTEM_FAULT
link = SL.MemoryLink()
eng = LE.LiveEngine(link, base, ml=None, log_path=os.path.join(tempfile.mkdtemp(), "a.log"), mode="rules")
st = eng.step()
check(st["overall"] == "SYSTEM_FAULT", "no data at all from the ESP32 -> SYSTEM_FAULT")

# ------------------------------------------------------------ 4. serial path with a fake COM port
import types, time as _time
class _FakeSerial:
    """Stands in for pyserial: returns recorded lines, records what the laptop writes."""
    instances = []
    def __init__(self):
        self.port = None; self.baudrate = None; self.timeout = None
        self.dtr = True; self.rts = True; self.is_open = False
        self._lines = []; self.written = bytearray(); self.dtr_at_open = None
        _FakeSerial.instances.append(self)
    def open(self):
        self.dtr_at_open = self.dtr; self.is_open = True
        with open(os.path.join(DATA_DIR, "demo_learn.txt"), encoding="utf-8") as fh:
            self._lines = fh.readlines()[:400]
    def readline(self):
        if self._lines:
            return self._lines.pop(0).encode()
        _time.sleep(0.2)
        return b""
    def write(self, b):
        self.written += b
    def close(self):
        self.is_open = False
sys.modules["serial"] = types.SimpleNamespace(Serial=_FakeSerial)
rec_path = os.path.join(tempfile.mkdtemp(), "rec.txt")
slink = SL.SerialLink("COM_FAKE", record_path=rec_path)
for _ in range(100):
    if slink.packets >= 50: break
    _time.sleep(0.05)
slink.send(ipc.T_HEARTBEAT)
slink.send(ipc.T_ALERT, bytes([90, 3, 0, 0]))
ser = _FakeSerial.instances[-1]
check(ser.dtr_at_open is False and ser.port == "COM_FAKE" and ser.baudrate == SERIAL_BAUD,
      "serial port opened at the configured baud with DTR low (no board reset)")
check(slink.packets >= 50, "reader thread turns lines from the port into beacon records")
check(os.path.getsize(rec_path) > 0, "raw lines are recorded to a file when asked")
check(ser.written[0] == 0xAA and ser.written[2] == ipc.T_HEARTBEAT and len(ser.written) == 8 + 4 + 8,
      "heartbeat and alert frames are written as CRC frames (8 + 8 + 4 bytes)")
slink.close()

print("\n" + ("ALL SELF-TESTS PASSED" if not failures else f"{len(failures)} SELF-TEST(S) FAILED"))
sys.exit(1 if failures else 0)
