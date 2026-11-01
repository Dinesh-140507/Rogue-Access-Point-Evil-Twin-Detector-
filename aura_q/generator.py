"""Step 1: synthetic Wi-Fi world. Produces beacon 'streams' (one per transmitter) and deauth bursts."""
import numpy as np
from config import *


def _ap(ssid, bssid, ch, sec, ie, rssi, std=2.0, jit=0.0004):
    return dict(ssid=ssid, bssid=bssid, channel=ch, security=sec, ie=ie, rssi=rssi, std=std, jit=jit)


CAMPUS1 = _ap("IIITB-Campus", "A4:2B:8C:11:00:01", 36, "WPA2-Enterprise", "ie_ent_a", -52)
CAMPUS2 = _ap("IIITB-Campus", "A4:2B:8C:11:00:02", 6, "WPA2-Enterprise", "ie_ent_a", -58)
LABGUEST = _ap("Lab-Guest", "A4:2B:8C:11:00:03", 11, "WPA2-PSK", "ie_psk_b", -61)
MESH1 = _ap("Home-Mesh", "C8:3A:35:22:00:01", 1, "WPA2-PSK", "ie_mesh", -55)
MESH2 = _ap("Home-Mesh", "C8:3A:35:22:00:02", 11, "WPA2-PSK", "ie_mesh", -63)
TRUSTED = [CAMPUS1, CAMPUS2, LABGUEST, MESH1, MESH2]


def make_stream(rng, ap, t0, t1, rssi_offset=0.0, jit=None, loss=0.03, dip=None,
                channel=None, security=None, ie=None, std=None, attack=False):
    """Beacons from ONE transmitter between t0 and t1."""
    jit = ap["jit"] if jit is None else jit
    n = int((t1 - t0) / BEACON_INTERVAL)
    t = t0 + np.arange(n) * BEACON_INTERVAL + rng.normal(0, jit, n)   # timing jitter
    keep = rng.random(n) > loss                                        # missed beacons
    idx = np.nonzero(keep)[0]
    t = t[keep]
    m = len(t)
    k = max(1, min(60, m))                                             # kernel can't exceed sample count
    slow = (np.convolve(rng.normal(0, 1, m), np.ones(k) / k, "same") * 3.0) if m else np.zeros(0)   # slow fading
    rssi = ap["rssi"] + rssi_offset + slow + rng.normal(0, ap["std"] if std is None else std, m)
    if dip is not None:                                                # person walking past (smooth ramp)
        a, b, db = dip
        ramp = np.clip((t - a) / 3.0, 0, 1) * np.clip((b - t) / 3.0, 0, 1)
        rssi = rssi - db * ramp
    seq = (rng.integers(0, 4096) + idx) % 4096                         # 12-bit sequence number
    return dict(ssid=ap["ssid"], bssid=ap["bssid"],
                channel=ap["channel"] if channel is None else channel,
                security=ap["security"] if security is None else security,
                ie=ap["ie"] if ie is None else ie,
                t=t, rssi=rssi, seq=seq, attack=attack)


def make_deauth(rng, bssid, t0, t1, rate):
    n = rng.poisson(rate * (t1 - t0))
    return dict(bssid=bssid, t=np.sort(rng.uniform(t0, t1, n)))


KINDS = ["normal", "obstacle", "low_sample", "mesh", "rogue_ap", "evil_twin", "stealth_twin"]
ATTACK_KINDS = ["rogue_ap", "evil_twin", "stealth_twin"]


def build(kind, seed):
    """Return (streams, deauths, truth) for one 120 s session."""
    rng = np.random.default_rng(seed)
    T = DURATION
    streams, deauths = [], []
    truth = dict(kind=kind, seed=seed, attack_start=None)

    for ap in TRUSTED:
        if kind == "obstacle" and ap is CAMPUS1:
            streams.append(make_stream(rng, ap, 0, T, dip=(50, 62, rng.uniform(6, 14))))
        elif kind == "low_sample" and ap is CAMPUS2:       # weak / intermittent signal for 30 s
            streams.append(make_stream(rng, ap, 0, 50))
            streams.append(make_stream(rng, ap, 50, 80, loss=0.97))
            streams.append(make_stream(rng, ap, 80, T))
        elif kind == "mesh" and ap is MESH1:               # approved mesh node switches channel
            streams.append(make_stream(rng, ap, 0, 55))
            streams.append(make_stream(rng, ap, 55, T, channel=6, rssi_offset=3.0))
        else:
            streams.append(make_stream(rng, ap, 0, T))

    if kind == "rogue_ap":                                 # unknown BSSID, protected SSID
        fake = dict(ssid="IIITB-Campus", bssid="DE:AD:BE:EF:%02X:%02X" % tuple(rng.integers(0, 256, 2)),
                    channel=int(rng.choice([1, 6, 11])), security="Open" if rng.random() < 0.6 else "WPA2-PSK",
                    ie="ie_soft_x", rssi=float(rng.uniform(-60, -38)), std=3.5, jit=0.004)
        streams.append(make_stream(rng, fake, ATTACK_START, T, attack=True))
        truth["attack_start"] = ATTACK_START

    if kind == "evil_twin":                                # SAME BSSID as CAMPUS1 (MAC spoofing)
        boost = rng.uniform(5, 25)                         # attacker is stronger by 5-25 dB
        twin = dict(CAMPUS1)
        streams.append(make_stream(
            rng, twin, ATTACK_START, T, rssi_offset=boost, jit=rng.uniform(0.001, 0.005), attack=True,
            channel=CAMPUS1["channel"] if rng.random() < 0.4 else int(rng.choice([1, 6, 11])),
            security=("Open" if rng.random() < 0.5 else "WPA2-PSK") if rng.random() < 0.7 else CAMPUS1["security"],
            ie="ie_ent_a" if rng.random() < 0.2 else "ie_soft_x"))
        if rng.random() < 0.5:                             # optional deauth burst for 20 s
            deauths.append(make_deauth(rng, CAMPUS1["bssid"], ATTACK_START, ATTACK_START + 20, 40))
        truth["attack_start"] = ATTACK_START

    if kind == "stealth_twin":                             # careful attacker: copies channel, security, IE; only +2..6 dB
        streams.append(make_stream(rng, dict(CAMPUS1), ATTACK_START, T, rssi_offset=rng.uniform(2, 6),
                                   jit=rng.uniform(0.0005, 0.002), attack=True))
        truth["attack_start"] = ATTACK_START

    if rng.random() < 0.3:                                 # cheap adapter: sequence numbers not reported
        for s in streams:
            s["seq"] = np.zeros_like(s["seq"])
    return streams, deauths, truth
