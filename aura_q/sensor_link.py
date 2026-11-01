"""Connection to the ESP32 sensor, plus two stand-ins used for testing and demos.

Lines the ESP32 sends (text, one per line, '|' separated):
  B|ch|rssi|seq|ts_us|bssid|security|ie_hash|ssid   beacon or probe response heard
  D|ch|ts_us|bssid                                  deauthentication frame heard
  S|uptime_ms|state|drops|rejects                   sensor status every 2 s
Lines starting with '#' are debug text and are ignored.

Frames the laptop sends to the ESP32 are binary CRC16 frames from ipc.py
(heartbeat every second, alert when a SUSPICIOUS window is found).

Three link classes share one interface:
  SerialLink  - real ESP32 on a USB port (COMx on Windows)
  ReplayLink  - plays a recorded session file back at real speed (demo safety net)
  MemoryLink  - used by selftest.py; you feed it lines directly
"""
import collections, threading, time
import ipc
from config import SERIAL_BAUD

KEEP_S = 180.0            # how much history to keep in memory (seconds)


def parse_line(line):
    """Turn one line from the ESP32 into a dict, or return None if it is malformed."""
    parts = line.rstrip("\r\n").split("|")
    kind = parts[0]
    try:
        if kind == "B" and len(parts) == 9:
            ch, rssi, seq, ts, bssid, sec, ie, ssid = parts[1:]
            return dict(kind="B", ch=int(ch), rssi=int(rssi), seq=int(seq), ts=int(ts),
                        bssid=bssid.upper(), security=sec, ie=ie, ssid=ssid)
        if kind == "D" and len(parts) == 4:
            ch, ts, bssid = parts[1:]
            return dict(kind="D", ch=int(ch), ts=int(ts), bssid=bssid.upper())
        if kind == "S" and len(parts) == 5:
            up, state, drops, rejects = parts[1:]
            return dict(kind="S", uptime_ms=int(up), state=state, drops=int(drops), rejects=int(rejects))
    except ValueError:
        return None
    return None


class _Clock:
    """The ESP32 timestamp is a 32-bit microsecond counter that wraps every ~71 minutes.
    This turns it into a steadily increasing number of seconds."""

    def __init__(self):
        self.prev = None
        self.wraps = 0

    def seconds(self, raw_us):
        if self.prev is not None and raw_us < self.prev - 2 ** 31:
            self.wraps += 1
        self.prev = raw_us
        return (raw_us + self.wraps * 2 ** 32) / 1e6


class LinkBase:
    """Stores what the sensor reports. Thread-safe enough for one writer and one reader."""

    def __init__(self):
        self.lock = threading.Lock()
        self.beacons = collections.deque()
        self.deauths = collections.deque()
        self.status = {"state": "UNKNOWN", "drops": 0, "rejects": 0}
        self.esp_clock = 0.0          # latest sensor time in seconds
        self.first_t = None           # sensor time of the first beacon
        self.packets = 0
        self.bad_lines = 0
        self.last_wall = None         # when the last line arrived (laptop clock)
        self._clock = _Clock()
        self.sender = ipc.Sender()
        self.sent_frames = 0

    def ingest(self, line):
        """Process one text line from the sensor."""
        if line.startswith("#") or not line.strip():
            return
        rec = parse_line(line)
        with self.lock:
            self.last_wall = time.monotonic()
            if rec is None:
                self.bad_lines += 1
                return
            if rec["kind"] == "S":
                self.status = rec
                return
            t = self._clock.seconds(rec["ts"])
            rec["t"] = t
            self.packets += 1
            if self.first_t is None:
                self.first_t = t
            self.esp_clock = max(self.esp_clock, t)
            target = self.beacons if rec["kind"] == "B" else self.deauths
            target.append(rec)
            cutoff = self.esp_clock - KEEP_S
            while target and target[0]["t"] < cutoff:
                target.popleft()

    def beacons_since(self, t0):
        with self.lock:
            return [b for b in self.beacons if b["t"] >= t0]

    def deauths_since(self, t0):
        with self.lock:
            return [d for d in self.deauths if d["t"] >= t0]

    def silence_s(self):
        """Seconds since the last line from the sensor (infinity if none yet)."""
        if self.last_wall is None:
            return float("inf")
        return time.monotonic() - self.last_wall

    def send(self, mtype, payload=b""):
        """Send one framed message to the ESP32 (heartbeat or alert)."""
        frame = self.sender.frame(mtype, payload)
        self._write(frame)
        self.sent_frames += 1

    def _write(self, frame):
        pass                          # overridden by SerialLink; replay and memory links ignore it


class MemoryLink(LinkBase):
    """No device and no thread: the caller feeds lines in. Used by the self-test."""


class ReplayLink(LinkBase):
    """Plays a recorded text file back at real speed (speed=2 means twice as fast).

    When the file loops, its sensor timestamps would restart from the beginning, which the
    clock would read as a huge time jump. So each pass is shifted forward by the length of
    the recording, and the time base keeps moving forward.
    """

    def __init__(self, path, speed=1.0, loop=True):
        super().__init__()
        self.path, self.speed, self.loop = path, speed, loop
        self.span_us = self._recording_span_us() + 1_000_000     # one idle second between passes
        self._stop = False
        self.thread = threading.Thread(target=self._play, daemon=True)
        self.thread.start()

    def _recording_span_us(self):
        clock, first, last = _Clock(), None, None
        with open(self.path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                p = parse_line(line)
                if p is not None and "ts" in p:
                    t = clock.seconds(p["ts"])
                    first = t if first is None else first
                    last = t
        return int(((last or 0) - (first or 0)) * 1e6)

    def _play(self):
        pass_no = 0
        while not self._stop:
            clock = _Clock()
            start_wall, start_t = time.monotonic(), None
            shift = pass_no * self.span_us
            with open(self.path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if self._stop:
                        return
                    p = parse_line(line)
                    if p is not None and "ts" in p:
                        t = clock.seconds(p["ts"])
                        if start_t is None:
                            start_t = t
                        wait = (start_wall + (t - start_t) / self.speed) - time.monotonic()
                        if wait > 0:
                            time.sleep(wait)
                        parts = line.rstrip("\r\n").split("|")
                        idx = 4 if p["kind"] == "B" else 2
                        parts[idx] = str((int(parts[idx]) + shift) & 0xFFFFFFFF)
                        line = "|".join(parts) + "\n"
                    self.ingest(line)
            if not self.loop:
                return
            pass_no += 1

    def stop(self):
        self._stop = True


class SerialLink(LinkBase):
    """The real ESP32 on a USB serial port."""

    def __init__(self, port, baud=SERIAL_BAUD, record_path=None):
        super().__init__()
        import serial                      # pyserial
        self.ser = serial.Serial()         # create closed first so the control lines can be set
        self.ser.port = port
        self.ser.baudrate = baud
        self.ser.timeout = 0.2
        self.ser.dtr = False               # opening a DevKit V1 port normally resets it; this avoids that
        self.ser.rts = False
        self.ser.open()
        self._wlock = threading.Lock()
        self._record = open(record_path, "w", encoding="utf-8") if record_path else None
        self._stop = False
        self.thread = threading.Thread(target=self._reader, daemon=True)
        self.thread.start()

    def _reader(self):
        while not self._stop:
            try:
                raw = self.ser.readline()
            except Exception:
                time.sleep(0.5)
                continue
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace")
            if self._record:
                self._record.write(line)
            self.ingest(line)

    def _write(self, frame):
        with self._wlock:
            self.ser.write(frame)

    def close(self):
        self._stop = True
        if self._record:
            self._record.close()
        self.ser.close()
