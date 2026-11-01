"""Step 4: explainable rules engine (PDF section 4.3).

Every test below either adds a clue or does not. Each clue is one of two kinds:
  strong = hard evidence about identity or security (BSSID, security mode, IE profile,
           a big RSSI jump, sequence collisions, deauthentication bursts)
  weak   = supporting evidence only (channel change, RSSI noise, timing jitter)

Decision:
  UNVERIFIED  - too few samples, or only weak clues, or a brand-new network
  SUSPICIOUS  - at least 2 clues AND at least 1 of them strong
  KNOWN       - no clues at all
"""
from config import *

SEV = {"KNOWN": 0, "UNVERIFIED": 1, "SUSPICIOUS": 2}


def classify(key, f, base):
    """Return (status, score 0-100, reasons, number_of_clues, number_of_strong_clues)."""
    ssid, bssid = key
    if f["n"] < MIN_SAMPLES:
        return "UNVERIFIED", 5, [f"low sample count ({f['n']} < {MIN_SAMPLES})"], 0, 0

    clues = []                       # (is_strong, weight, text)
    ref = base["aps"].get(bssid)     # is this exact BSSID in the trusted registry?
    sref = base["ssids"].get(ssid)   # is this SSID (network name) in the registry?

    if ref is None:                  # unknown BSSID
        if sref is None and ssid not in PROTECTED_SSIDS:
            return "UNVERIFIED", 10, [f"new BSSID {bssid} on unprotected SSID '{ssid}'"], 0, 0
        clues.append((True, 30, f"SSID '{ssid}' observed with unverified BSSID {bssid}"))
        if sref is None:             # protected name, but no profile has been learned for it yet
            return "UNVERIFIED", 30, [clues[0][2],
                    "no trusted profile for this protected SSID yet - learn it first"], 1, 1
        ref_sec, ref_ie = set(sref["security"]), set(sref["ie"])
        ref_ch = None
        if f["mean"] > sref["rssi_max"] + RSSI_DEV_DB:
            clues.append((True, 20, f"mean RSSI {f['mean']:.0f} dBm is "
                          f"{f['mean'] - sref['rssi_max']:.0f} dB above the strongest approved AP"))
    else:                            # known BSSID: compare with its own baseline
        ref_sec, ref_ie, ref_ch = set(ref["security"]), set(ref["ie"]), set(ref["channels"])
        dev = f["mean"] - ref["rssi_mean"]
        if abs(dev) > RSSI_DEV_DB:
            clues.append((True, 20, f"mean RSSI {f['mean']:.0f} dBm deviates {dev:+.0f} dB "
                          f"from baseline {ref['rssi_mean']:.0f} dBm"))

    if f["securities"] - ref_sec:
        clues.append((True, 30, f"security {sorted(f['securities'])} differs from baseline {sorted(ref_sec)}"))
    if f["ie"] - ref_ie:
        clues.append((True, 20, "802.11 IE capability profile differs from baseline"))
    if ref_ch is not None and f["channels"] - ref_ch:
        clues.append((False, 10, f"channel {sorted(f['channels'])} not in baseline {sorted(ref_ch)}"))
    if f["std"] > RSSI_STD_MAX:
        clues.append((False, 10, f"RSSI std-dev {f['std']:.1f} dB > {RSSI_STD_MAX:.0f} dB"))
    if f["jitter_ms"] > JITTER_MS_MAX:
        clues.append((False, 10, f"beacon timing jitter {f['jitter_ms']:.1f} ms"))
    if f["seq_jump"] > SEQ_JUMP_MAX:
        clues.append((True, 20, f"sequence-number discontinuities ({f['seq_jump'] * 100:.0f}% of steps)"))
    if f["deauth_rate"] > DEAUTH_RATE_MAX:
        clues.append((True, 20, f"deauthentication burst ({f['deauth_rate']:.0f} frames/s)"))

    total, strong = len(clues), sum(c[0] for c in clues)
    score = min(100, sum(c[1] for c in clues))
    reasons = [c[2] for c in clues]
    if strong >= 1 and total >= 2:
        return "SUSPICIOUS", score, reasons, total, strong
    if total >= 1:
        return "UNVERIFIED", score, reasons, total, strong
    return "KNOWN", 0, [], 0, 0
