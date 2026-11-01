"""Step 7: STM32U585 watchdog state machine, simulated in Python (port to mcu_watchdog.ino later).
States: BOOT -> HEALTHY -> ALERT / COMM_FAULT -> RECOVERY -> HEALTHY"""
from config import *
import ipc


class McuWatchdog:
    def __init__(self):
        self.state = "BOOT"
        self.last_valid = None
        self.last_seq = None
        self.bad = []            # timestamps of rejected frames
        self.streak = 0          # consecutive valid frames since last fault
        self.alert_until = -1.0
        self.rejects = {}
        self.fault_times = []

    def on_bytes(self, t, raw):
        ok, reason, msg = ipc.parse_frame(raw)
        if ok and self.last_seq is not None and not ipc.seq_newer(msg["seq"], self.last_seq):
            ok, reason = False, "bad_seq"           # replayed / out-of-order
        if not ok:
            self.bad.append(t)
            self.rejects[reason] = self.rejects.get(reason, 0) + 1
            return False
        self.last_seq, self.last_valid = msg["seq"], t
        self.streak += 1
        if msg["type"] == ipc.T_ALERT:
            self.alert_until = t + ALERT_HOLD
        return True

    def tick(self, t):
        self.bad = [b for b in self.bad if t - b <= BAD_WINDOW]
        ref = self.last_valid if self.last_valid is not None else 0.0
        faulty = (t - ref) > WD_TIMEOUT or len(self.bad) >= BAD_THRESH
        if faulty:
            if self.state != "COMM_FAULT":
                self.state = "COMM_FAULT"; self.fault_times.append(t)
            self.streak = 0
        elif self.state == "BOOT":
            if self.last_valid is not None:
                self.state = "HEALTHY"
        elif self.state == "COMM_FAULT":
            self.state = "RECOVERY"
        elif self.state == "RECOVERY":
            if self.streak >= RECOVERY_CYCLES:
                self.state = "HEALTHY"
        elif self.state == "HEALTHY" and t < self.alert_until:
            self.state = "ALERT"
        elif self.state == "ALERT" and t >= self.alert_until:
            self.state = "HEALTHY"
        return self.state


def run_mcu(events, duration, dt=0.05):
    """events = [(time, raw_bytes), ...]. Returns (watchdog, timeline[(t, state)])."""
    events = sorted(events, key=lambda e: e[0])
    wd, i, t, tl = McuWatchdog(), 0, 0.0, []
    while t <= duration + 1e-9:
        while i < len(events) and events[i][0] <= t:
            wd.on_bytes(events[i][0], events[i][1]); i += 1
        tl.append((round(t, 3), wd.tick(t)))
        t += dt
    return wd, tl


def heartbeats(sender, t0, t1):
    ev, t = [], t0
    while t < t1 - 1e-9:
        ev.append((t, sender.frame(ipc.T_HEARTBEAT))); t += HB_PERIOD
    return ev
