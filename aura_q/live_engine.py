"""Live analysis: sensor records -> per-window features -> rules (+ optional ML) -> status.

step() is called every LIVE_STEP_S seconds by live_app.py. It publishes a state dictionary
that the dashboard reads, writes alerts to a log file, and asks for an alert frame to be
sent to the ESP32 when a window is SUSPICIOUS.
"""
import collections, json, os, time
from collections import defaultdict
import numpy as np
from config import *
import baseline, features, pipeline, rules
from ml import AnomalyModel

SEV = rules.SEV


def shifted(records, t0):
    """Copies of the records with time counted from t0 (used when learning a baseline)."""
    return [dict(r, t=r["t"] - t0) for r in records]


def to_streams(beacons):
    """Group beacon records into the stream format features.py expects.

    One stream per (SSID, BSSID, channel, security, IE). The sensor reports every beacon
    separately, so the arrays are simply the time, RSSI and sequence number of each beacon.
    """
    groups = defaultdict(list)
    for b in beacons:
        groups[(b["ssid"], b["bssid"], b["ch"], b["security"], b["ie"])].append(b)
    streams = []
    for (ssid, bssid, ch, sec, ie), rows in groups.items():
        streams.append(dict(ssid=ssid, bssid=bssid, channel=ch, security=sec, ie=ie,
                            t=np.array([r["t"] for r in rows]),
                            rssi=np.array([r["rssi"] for r in rows], dtype=float),
                            seq=np.array([r["seq"] for r in rows])))
    return streams


def to_deauths(deauths):
    groups = defaultdict(list)
    for d in deauths:
        groups[d["bssid"]].append(d["t"])
    return [dict(bssid=b, t=np.array(ts)) for b, ts in groups.items()]


def learn_baseline(beacons, deauths, duration, use_ml=False):
    """Learn the trusted baseline from a recording of a clean network. Returns (base, ml_or_None)."""
    streams, dl = to_streams(beacons), to_deauths(deauths)
    base = baseline.learn([(streams, dl)], window=LIVE_WINDOW_S, duration=duration)
    ml = None
    if use_ml:
        feats = []
        for _, _, f in features.featurize(streams, dl, duration=duration, window=LIVE_WINDOW_S):
            feats += [v for k, v in f.items() if k[1] in base["aps"] and v["n"] >= MIN_SAMPLES]
        if feats:
            ml = AnomalyModel().fit(feats)
    return base, ml


class LiveEngine:
    def __init__(self, link, base, ml=None, log_path=ALERT_LOG, mode=LIVE_MODE):
        self.link, self.base, self.ml, self.mode = link, base, ml, mode
        self.log_path = log_path
        os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
        self.prev = {}
        self.alerts = collections.deque(maxlen=50)
        self._last_logged = {}        # (ssid, bssid) -> wall time of last log entry
        self.on_alert = None          # callback(score, n_reasons): sends an alert frame to the ESP32
        self.state = dict(overall="WAITING", headline="starting", aps=[], alerts=[],
                          sensor={}, window_s=LIVE_WINDOW_S, updated=time.strftime("%H:%M:%S"))

    # ------------------------------------------------------------------ one analysis step
    def step(self):
        link = self.link
        now_t = link.esp_clock
        silence = link.silence_s()
        sensor = dict(silence_s=None if silence == float("inf") else round(silence, 1),
                      firmware_state=link.status.get("state", "?"),
                      drops=link.status.get("drops", 0), rejects=link.status.get("rejects", 0),
                      packets=link.packets)
        if silence > SENSOR_TIMEOUT_S:
            msg = ("no data from the ESP32 yet - check the USB cable, the COM port and the board"
                   if silence == float("inf") else
                   f"no data from the ESP32 for {silence:.0f} s - check the USB cable and the board")
            return self._publish("SYSTEM_FAULT", msg, [], sensor)
        if link.first_t is None or now_t - link.first_t < LIVE_WINDOW_S:
            return self._publish("WAITING", "collecting the first analysis window", [], sensor)

        ws = now_t - LIVE_WINDOW_S
        streams = to_streams(link.beacons_since(ws))
        dl = to_deauths(link.deauths_since(ws))
        feats = features.extract_window(streams, dl, ws, now_t, self.prev)
        self.prev.update({k: v["mean"] for k, v in feats.items()})
        if not feats:
            return self._publish("WAITING", "no beacons heard in the last window", [], sensor)

        rows = []
        for c in pipeline.classify_keys(feats, self.base, self.ml, self.mode):
            f = feats[c["key"]]
            rows.append(dict(ssid=c["key"][0], bssid=c["key"][1], status=c["status"], score=c["score"],
                             mean_rssi=round(f["mean"], 1), samples=f["n"], reasons=c["reasons"]))
        rows.sort(key=lambda r: (-SEV[r["status"]], -r["score"]))
        worst = rows[0]

        if worst["status"] == "SUSPICIOUS":
            self._log_alert(worst)
            if self.on_alert:
                self.on_alert(worst["score"], len(worst["reasons"]))
            headline = (f"SUSPICIOUS: SSID '{worst['ssid']}' from BSSID {worst['bssid']} - "
                        f"{worst['reasons'][0]}")
        elif worst["status"] == "UNVERIFIED":
            headline = "Some networks need more samples or show an unexplained change"
        else:
            headline = "Every network heard matches the trusted baseline"
        return self._publish(worst["status"], headline, rows, sensor)

    # ------------------------------------------------------------------ helpers
    def _log_alert(self, row):
        """Write an alert to the forensic log, at most once every 30 s per network."""
        key = (row["ssid"], row["bssid"])
        now = time.time()
        if now - self._last_logged.get(key, 0) < 30:
            return
        self._last_logged[key] = now
        entry = dict(time=time.strftime("%Y-%m-%d %H:%M:%S"), status=row["status"], score=row["score"],
                     ssid=row["ssid"], bssid=row["bssid"], mean_rssi=row["mean_rssi"],
                     samples=row["samples"], reasons=row["reasons"])
        self.alerts.appendleft(entry)
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    def _publish(self, overall, headline, rows, sensor):
        self.state = dict(overall=overall, headline=headline, aps=rows[:60], alerts=list(self.alerts),
                          sensor=sensor, window_s=LIVE_WINDOW_S,
                          updated=time.strftime("%H:%M:%S"))
        return self.state
