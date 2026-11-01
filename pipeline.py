"""Glue between features, rules and the optional ML model.

Modes:  rules  - rules engine only (the fallback if the ML part is disabled)
        ml     - anomaly model only (for comparison)
        hybrid - rules decide; the ML model may only confirm a window that already has a strong clue
"""
import rules
from config import *


def classify_keys(feats, base, ml=None, mode="hybrid"):
    """Classify every (SSID, BSSID) in one window. Returns one dict per key."""
    keys = list(feats)
    flags = ml.flags([feats[k] for k in keys]) if (ml is not None and mode != "rules") else [False] * len(keys)
    out = []
    for k, flag in zip(keys, flags):
        f = feats[k]
        st, score, reasons, nclues, nstrong = rules.classify(k, f, base)
        if mode == "ml":
            if f["n"] < MIN_SAMPLES:
                st, score, reasons = "UNVERIFIED", 5, ["low sample count"]
            elif flag:
                st, score, reasons = "SUSPICIOUS", 70, ["ML anomaly score above threshold"]
            else:
                st, score, reasons = "KNOWN", 0, []
        elif mode == "hybrid" and flag and st != "SUSPICIOUS" and nstrong >= 1:
            st, score, reasons = "SUSPICIOUS", max(score, 60), reasons + ["ML anomaly confirms a rule clue"]
        out.append(dict(status=st, score=score, reasons=reasons, key=k, n=f["n"]))
    return out


def classify_windows(featwins, base, ml=None, mode="hybrid"):
    """Classify a list of [(ws, we, feats)] windows. Returns the worst status per window."""
    out = []
    for ws, we, feats in featwins:
        worst = dict(status="KNOWN", score=0, reasons=[], key=None, n=0)
        for c in classify_keys(feats, base, ml, mode):
            if (rules.SEV[c["status"]], c["score"]) > (rules.SEV[worst["status"]], worst["score"]):
                worst = c
        out.append(dict(ws=ws, we=we, **worst))
    return out


def format_alert(w):
    """One human-readable line: status, risk score, window, and every reason."""
    ssid, bssid = w["key"]
    head = f"[{w['status']} - Risk Score: {w['score']}/100 | Window: {w['we'] - w['ws']:.0f} s ({w['n']} samples)]"
    return head + f" SSID '{ssid}', BSSID {bssid}: " + "; ".join(w["reasons"]) + "."
