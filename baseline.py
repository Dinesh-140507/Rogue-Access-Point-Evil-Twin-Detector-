"""Step 3: learn the Trusted AP Baseline Registry and store it in SQLite.

In the PDF this database lives on the board's eMMC. Here it is a plain .db file.
"""
import json, os, sqlite3
import numpy as np
from config import *
from features import featurize


def learn(sessions, window=WINDOW_S, duration=DURATION):
    """sessions = [(streams, deauths), ...] recorded from networks that are known to be clean."""
    acc = {}
    for streams, deauths in sessions:
        for _, _, feats in featurize(streams, deauths, duration=duration, window=window):
            for (ssid, bssid), f in feats.items():
                if f["n"] < MIN_SAMPLES:
                    continue
                a = acc.setdefault(bssid, dict(ssid=ssid, means=[], ch=set(), sec=set(), ie=set()))
                a["means"].append(f["mean"]); a["ch"] |= f["channels"]
                a["sec"] |= f["securities"]; a["ie"] |= f["ie"]
    aps = {b: dict(ssid=a["ssid"], rssi_mean=float(np.mean(a["means"])), channels=sorted(a["ch"]),
                   security=sorted(a["sec"]), ie=sorted(a["ie"])) for b, a in acc.items()}
    return _with_ssids(aps)


def _with_ssids(aps):
    """Add a per-SSID summary (the 'expected' security and IE of a protected network name)."""
    ssids = {}
    for p in aps.values():
        s = ssids.setdefault(p["ssid"], dict(security=set(), ie=set(), channels=set(), rssi_max=-999.0))
        s["security"] |= set(p["security"]); s["ie"] |= set(p["ie"]); s["channels"] |= set(p["channels"])
        s["rssi_max"] = max(s["rssi_max"], p["rssi_mean"])
    return dict(aps=aps, ssids={k: dict(v, security=sorted(v["security"]), ie=sorted(v["ie"]),
                                        channels=sorted(v["channels"])) for k, v in ssids.items()})


def save(base, path=SIM_BASELINE):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE IF NOT EXISTS trusted_ap(bssid TEXT PRIMARY KEY, profile TEXT)")
    con.execute("DELETE FROM trusted_ap")
    for b, p in base["aps"].items():
        con.execute("INSERT INTO trusted_ap VALUES (?,?)", (b, json.dumps(p)))
    con.commit(); con.close()


def load(path=SIM_BASELINE):
    con = sqlite3.connect(path)
    aps = {b: json.loads(p) for b, p in con.execute("SELECT bssid, profile FROM trusted_ap")}
    con.close()
    return _with_ssids(aps)
