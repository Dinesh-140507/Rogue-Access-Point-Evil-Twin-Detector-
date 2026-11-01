"""Step 2: sliding-window feature extractor (PDF section 4.2).

For every (SSID, BSSID) pair seen in a window, it computes RSSI statistics,
beacon timing jitter, sequence-number jumps, deauthentication rate, and the
sets of channels, security modes and IE (capability) fingerprints.
"""
import numpy as np
from config import *


def jitter_ms(t):
    """Std-dev of the inter-beacon time residual, robust to lost beacons."""
    if len(t) < 3:
        return 0.0
    d = np.diff(t)
    k = np.maximum(1, np.round(d / BEACON_INTERVAL))
    return float(np.std(d / k - BEACON_INTERVAL) * 1000)


def seq_jump_ratio(seq, t):
    """Fraction of consecutive 12-bit sequence steps that are not 'small forward'.

    Two transmitters on one channel produce sequence collisions (an evil twin next to
    the real AP). Only pairs of frames closer than 0.25 s are compared, so the gaps caused
    by the ESP32 hopping between channels are not mistaken for sequence jumps.
    A driver that does not report sequence numbers (all zeros) gives 0.
    """
    if len(seq) < 3 or np.ptp(seq) == 0:
        return 0.0
    close = np.diff(t) <= 0.25
    if close.sum() < 2:
        return 0.0
    d = (np.diff(seq) % 4096)[close]
    return float(np.mean((d == 0) | (d > 8)))


def extract_window(streams, deauths, ws, we, prev_means):
    """Features for one window [ws, we). Returns {(ssid, bssid): feature dict}."""
    groups = {}
    for s in streams:
        m = (s["t"] >= ws) & (s["t"] < we)
        if not m.any():
            continue
        g = groups.setdefault((s["ssid"], s["bssid"]),
                              dict(t=[], rssi=[], seq=[], ch=set(), sec=set(), ie=set()))
        g["t"].append(s["t"][m]); g["rssi"].append(s["rssi"][m]); g["seq"].append(s["seq"][m])
        g["ch"].add(s["channel"]); g["sec"].add(s["security"]); g["ie"].add(s["ie"])
    dcount = {}
    for d in deauths:
        dcount[d["bssid"]] = dcount.get(d["bssid"], 0) + int(((d["t"] >= ws) & (d["t"] < we)).sum())
    out = {}
    for key, g in groups.items():
        t = np.concatenate(g["t"]); o = np.argsort(t)
        t, r, q = t[o], np.concatenate(g["rssi"])[o], np.concatenate(g["seq"])[o]
        mean = float(r.mean())
        out[key] = dict(n=len(t), mean=mean, median=float(np.median(r)), min=float(r.min()),
                        max=float(r.max()), std=float(r.std()),
                        delta=mean - prev_means.get(key, mean),
                        jitter_ms=jitter_ms(t), seq_jump=seq_jump_ratio(q, t),
                        deauth_rate=dcount.get(key[1], 0) / (we - ws),
                        channels=g["ch"], securities=g["sec"], ie=g["ie"])
    return out


def featurize(streams, deauths, duration=DURATION, window=WINDOW_S, step=STEP_S):
    """Slide a window over a whole session. Returns [(ws, we, feats), ...]."""
    wins, prev, ws = [], {}, 0.0
    while ws + window <= duration + 1e-9:
        f = extract_window(streams, deauths, ws, ws + window, prev)
        wins.append((ws, ws + window, f))
        prev.update({k: v["mean"] for k, v in f.items()})
        ws += step
    return wins
