"""Simulation runner: tests the whole algorithm on synthetic Wi-Fi sessions. No hardware needed.

    python run_all.py [runs_per_scenario]      (default 30; use 10 for a quick test)

Outputs (in ./results): summary.md, metrics.csv, validation.csv, baseline.db, fig1..fig4.png
"""
import os, sys, csv, struct
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from config import *
import generator as G
import features, baseline, pipeline, ipc, watchdog
from ml import AnomalyModel

N = int(sys.argv[1]) if len(sys.argv) > 1 else 30
os.makedirs(RESULTS_DIR, exist_ok=True)
out = []                                              # lines for summary.md


def say(s=""):
    print(s); out.append(s)


# ---------------------------------------------------------------- 1. baseline + ML training
train_sessions = [G.build("normal", 2000 + i)[:2] for i in range(20)]
base = baseline.learn(train_sessions)
baseline.save(base, SIM_BASELINE)
base = baseline.load(SIM_BASELINE)                    # proves the SQLite round trip works
say(f"Baseline learned for {len(base['aps'])} trusted APs (stored in {SIM_BASELINE})")

ml_feats = []
for kind in ["normal", "obstacle", "mesh"]:
    for i in range(40):
        s, d, _ = G.build(kind, 1000 + i)
        for _, _, f in features.featurize(s, d):
            ml_feats += [v for k, v in f.items() if k[1] in base["aps"] and v["n"] >= MIN_SAMPLES]
ml = AnomalyModel().fit(ml_feats)
say(f"Isolation Forest trained on {len(ml_feats)} benign windows (different seeds from the test set)")

# ---------------------------------------------------------------- 2. run the test sessions
runs = []
for kind in G.KINDS:
    for seed in range(N):
        s, d, truth = G.build(kind, seed)
        runs.append(dict(kind=kind, seed=seed, truth=truth, fw=features.featurize(s, d)))
say(f"Simulated {len(runs)} sessions ({N} per scenario, {DURATION:.0f} s each)\n")


def score_run(wins, truth):
    a = truth["attack_start"]
    tp = fp = tn = fn = 0
    lat = None
    for w in wins:
        pred = w["status"] == "SUSPICIOUS"
        if a is not None and pred and w["we"] > a and lat is None:
            lat = w["we"] - a
        if a is None or w["we"] <= a:
            label = False
        elif w["we"] <= a + 3.0:
            continue                                  # too little attack data in the window yet
        else:
            label = True
        tp += pred and label; fn += (not pred) and label
        fp += pred and (not label); tn += (not pred) and (not label)
    return dict(tp=tp, fp=fp, tn=tn, fn=fn, lat=lat)


results = {}
for mode in ["rules", "ml", "hybrid"]:
    for r in runs:
        r[mode] = pipeline.classify_windows(r["fw"], base, ml if mode != "rules" else None, mode)
        r[mode + "_score"] = score_run(r[mode], r["truth"])
    tot = {k: sum(r[mode + "_score"][k] for r in runs) for k in ["tp", "fp", "tn", "fn"]}
    atk = [r for r in runs if r["truth"]["attack_start"] is not None]
    lats = [r[mode + "_score"]["lat"] for r in atk if r[mode + "_score"]["lat"] is not None]
    results[mode] = dict(
        acc=(tot["tp"] + tot["tn"]) / max(1, sum(tot.values())),
        recall=tot["tp"] / max(1, tot["tp"] + tot["fn"]),
        precision=tot["tp"] / max(1, tot["tp"] + tot["fp"]),
        far=tot["fp"] / max(1, tot["fp"] + tot["tn"]),
        run_detect=len(lats) / max(1, len(atk)),
        lat_med=float(np.median(lats)) if lats else float("nan"),
        lat_p95=float(np.percentile(lats, 95)) if lats else float("nan"),
        lats=lats, **tot)

say("## Overall detection metrics (window level; SUSPICIOUS = positive)")
say("| Mode | Accuracy | Recall | Precision | False-alarm rate | Runs detected | Median latency (s) | 95th pct latency (s) |")
say("|---|---|---|---|---|---|---|---|")
for m, v in results.items():
    say(f"| {m} | {v['acc']:.4f} | {v['recall']:.3f} | {v['precision']:.3f} | {v['far']:.4f} | "
        f"{v['run_detect'] * 100:.1f}% | {v['lat_med']:.1f} | {v['lat_p95']:.1f} |")

say("\n## Per scenario (hybrid mode)")
say("| Scenario | Runs | Runs with >=1 SUSPICIOUS | Detected after onset | Median latency (s) |")
say("|---|---|---|---|---|")
per_kind = {}
for kind in G.KINDS:
    rs = [r for r in runs if r["kind"] == kind]
    anysus = sum(any(w["status"] == "SUSPICIOUS" for w in r["hybrid"]) for r in rs)
    lats = [r["hybrid_score"]["lat"] for r in rs if r["hybrid_score"]["lat"] is not None]
    per_kind[kind] = dict(runs=len(rs), anysus=anysus, det=len(lats), lats=lats)
    med = f"{np.median(lats):.1f}" if lats else "-"
    det = f"{len(lats)}/{len(rs)}" if kind in G.ATTACK_KINDS else "-"
    say(f"| {kind} | {len(rs)} | {anysus} | {det} | {med} |")

# ---------------------------------------------------------------- 3. Linux -> MCU end-to-end latency
mcu_lats = []
frame_bytes = len(ipc.build_frame(ipc.T_ALERT, 1, bytes(4)))
serial_s = frame_bytes * 10 / UART_BAUD
for r in [r for r in runs if r["truth"]["attack_start"] is not None]:
    snd, ev = ipc.Sender(), []
    ev += watchdog.heartbeats(snd, 0, DURATION)
    for w in r["hybrid"]:
        if w["status"] == "SUSPICIOUS":
            # NOTE: the window end is used as the 'computed' time, so compute time is not included.
            ev.append((w["we"] + serial_s, snd.frame(ipc.T_ALERT, bytes([min(w["score"], 255), 2, 10, 0]))))
    _, tl = watchdog.run_mcu(ev, DURATION)
    t_alert = next((t for t, s in tl if s == "ALERT" and t > r["truth"]["attack_start"]), None)
    if t_alert is not None:
        mcu_lats.append(t_alert - r["truth"]["attack_start"])
say(f"\nEnd-to-end attack onset -> MCU ALERT state: median {np.median(mcu_lats):.2f} s, "
    f"95th pct {np.percentile(mcu_lats, 95):.2f} s over {len(mcu_lats)} detected attack runs "
    f"(UART frame time at {UART_BAUD} baud = {serial_s * 1000:.1f} ms; compute time not modelled)")

# ---------------------------------------------------------------- 4. watchdog tests (validation 5 and 6)
rng = np.random.default_rng(7)
delays = []
for _ in range(200):                                  # T5: capture process crashes at a random time
    tc = rng.uniform(10, 11)
    ev = watchdog.heartbeats(ipc.Sender(), 0, tc)
    wd, tl = watchdog.run_mcu(ev, 20)
    t_fault = next(t for t, s in tl if s == "COMM_FAULT")
    delays.append(t_fault - tc)
delays = np.array(delays)
say(f"\nWatchdog fault-detection delay after capture crash: mean {delays.mean():.2f} s, "
    f"max {delays.max():.2f} s (200 trials)")

good = ipc.build_frame(ipc.T_STATUS, 5, b"abcd")      # T6: random bit flips in valid frames
rejected = tested = 0
while tested < 2000:
    b = bytearray(good)
    for _ in range(rng.integers(1, 4)):
        pos, bit = rng.integers(0, len(b)), rng.integers(0, 8)
        b[pos] ^= 1 << bit
    if bytes(b) == good:                              # flips cancelled out: not a corruption
        continue
    tested += 1
    rejected += not ipc.parse_frame(bytes(b))[0]

oversized = bytes([0xAA, 1, 1, 0, 1, 99]) + bytes(99) + b"\0\0"
bad_type = bytearray(ipc.build_frame(ipc.T_STATUS, 6))
bad_type[2] = 0x7F
bad_type[-2:] = struct.pack(">H", ipc.crc16_ccitt(bytes(bad_type[1:-2])))   # valid CRC, unknown type
rej_special = [ipc.parse_frame(oversized)[1], ipc.parse_frame(bytes(bad_type))[1]]

wd_burst = watchdog.heartbeats(ipc.Sender(), 0, 30)
wd_burst += [(10 + 0.2 * i, bytes(rng.integers(0, 256, 12, dtype=np.uint8))) for i in range(10)]
wd6, tl6 = watchdog.run_mcu(wd_burst, 30)
fault6 = any(s == "COMM_FAULT" for t, s in tl6)
rec6 = tl6[-1][1]
say(f"IPC corruption: {rejected}/{tested} bit-flipped frames rejected; special cases rejected as {rej_special}; "
    f"garbage burst -> COMM_FAULT={fault6}, final state={rec6}; reject reasons={wd6.rejects}")


# ---------------------------------------------------------------- 5. the 9 validation tests (PDF 5.2)
def frac(kind, pred):
    rs = [r for r in runs if r["kind"] == kind]
    return sum(pred(r) for r in rs) / len(rs)


sus = lambda r: any(w["status"] == "SUSPICIOUS" for w in r["hybrid"])
unv = lambda r: any(w["status"] == "UNVERIFIED" for w in r["hybrid"])
chan = lambda r: any("channel" in " ".join(w["reasons"]) for w in r["hybrid"])
rules_detects = lambda r: r["rules_score"]["lat"] is not None
V = []
V.append(("1 Normal baseline stability", "Runs with any SUSPICIOUS <= 5%",
          f"{frac('normal', sus) * 100:.1f}%", frac("normal", sus) <= 0.05))
V.append(("2 Environmental obstacle", "Runs with any SUSPICIOUS <= 5%",
          f"{frac('obstacle', sus) * 100:.1f}%", frac("obstacle", sus) <= 0.05))
d3 = per_kind["evil_twin"]["det"] / N
l3 = np.median(per_kind["evil_twin"]["lats"]) if per_kind["evil_twin"]["lats"] else 99
V.append(("3 Evil-twin canary", "Detected >= 90% and median latency <= 10 s",
          f"{d3 * 100:.1f}% / {l3:.1f} s", d3 >= 0.9 and l3 <= 10))
V.append(("4 Low-sample guardrail", "UNVERIFIED shown, SUSPICIOUS in <= 5% of runs",
          f"UNVERIFIED {frac('low_sample', unv) * 100:.0f}%, SUSPICIOUS {frac('low_sample', sus) * 100:.1f}%",
          frac("low_sample", unv) >= 0.95 and frac("low_sample", sus) <= 0.05))
V.append(("5 Capture process crash", "COMM_FAULT within 3 s",
          f"max {delays.max():.2f} s", delays.max() <= WD_TIMEOUT + 0.06))
V.append(("6 IPC corruption injection", "100% rejected + fault state",
          f"{rejected}/{tested}, fault={fault6}",
          rejected == tested and fault6 and all(x != "ok" for x in rej_special)))
V.append(("7 Dashboard independence", "Alerts continue with Flask stopped",
          "NOT SIMULATED - verify on the board", None))
rules_rate = sum(rules_detects(r) for r in runs if r["kind"] == "evil_twin") / N
V.append(("8 ML fallback resilience", "Rules-only mode still detects >= 80% of evil twins",
          f"{rules_rate * 100:.1f}% detected with rules only", rules_rate >= 0.8))
V.append(("9 Legit roaming / mesh", "SUSPICIOUS <= 5% and channel change logged",
          f"SUSPICIOUS {frac('mesh', sus) * 100:.1f}%, logged {frac('mesh', chan) * 100:.0f}%",
          frac("mesh", sus) <= 0.05 and frac("mesh", chan) >= 0.9))
say("\n## Validation tests (PDF section 5.2)")
say("| Test | Pass criterion | Measured | Result |")
say("|---|---|---|---|")
for n, c, m, ok in V:
    say(f"| {n} | {c} | {m} | {'PASS' if ok else ('N/A' if ok is None else 'FAIL')} |")

demo = next(r for r in runs if r["kind"] == "evil_twin" and r["hybrid_score"]["lat"] is not None)
w = next(w for w in demo["hybrid"] if w["status"] == "SUSPICIOUS" and w["we"] > ATTACK_START)
say("\nExample explainable alert (evil_twin seed %d):\n%s" % (demo["seed"], pipeline.format_alert(w)))

# ---------------------------------------------------------------- 6. save tables and figures
with open(os.path.join(RESULTS_DIR, "summary.md"), "w") as f:
    f.write("\n".join(out) + "\n")
with open(os.path.join(RESULTS_DIR, "metrics.csv"), "w", newline="") as f:
    wr = csv.writer(f)
    wr.writerow(["mode", "accuracy", "recall", "precision", "false_alarm_rate", "runs_detected",
                 "latency_median_s", "latency_p95_s"])
    for m, v in results.items():
        wr.writerow([m, f"{v['acc']:.4f}", f"{v['recall']:.4f}", f"{v['precision']:.4f}",
                     f"{v['far']:.5f}", f"{v['run_detect']:.4f}", f"{v['lat_med']:.2f}", f"{v['lat_p95']:.2f}"])
with open(os.path.join(RESULTS_DIR, "validation.csv"), "w", newline="") as f:
    wr = csv.writer(f)
    wr.writerow(["test", "criterion", "measured", "result"])
    for n, c, m, ok in V:
        wr.writerow([n, c, m, "PASS" if ok else ("N/A" if ok is None else "FAIL")])

plt.rcParams.update({"font.size": 9})
fig, ax = plt.subplots(2, 1, figsize=(7, 5), sharex=True)
key = ("IIITB-Campus", G.CAMPUS1["bssid"])
xs = [(ws + we) / 2 for ws, we, f in demo["fw"] if key in f]
ys = [f[key]["mean"] for ws, we, f in demo["fw"] if key in f]
ax[0].plot(xs, ys, "k-"); ax[0].axvline(ATTACK_START, color="k", ls="--", label="attack onset")
ax[0].axvline(ATTACK_START + demo["hybrid_score"]["lat"], color="k", ls=":", label="first SUSPICIOUS")
ax[0].set_ylabel("Mean RSSI of the genuine AP (dBm)"); ax[0].legend()
ax[0].set_title("Evil-twin run: RSSI and decision per window")
lvl = {"KNOWN": 0, "UNVERIFIED": 1, "SUSPICIOUS": 2}
ax[1].step([(w["ws"] + w["we"]) / 2 for w in demo["hybrid"]], [lvl[w["status"]] for w in demo["hybrid"]],
           "k-", where="mid")
ax[1].set_yticks([0, 1, 2]); ax[1].set_yticklabels(["KNOWN", "UNVERIFIED", "SUSPICIOUS"])
ax[1].set_xlabel("Time (s)")
plt.tight_layout(); plt.savefig(os.path.join(RESULTS_DIR, "fig1_evil_twin_timeline.png"), dpi=150); plt.close()

plt.figure(figsize=(6, 3.5))
for m, ls in [("rules", "-"), ("hybrid", "--")]:
    plt.hist(results[m]["lats"], bins=range(0, 62, 2), histtype="step", color="k", linestyle=ls, label=m)
plt.xlabel("Detection latency after attack onset (s)"); plt.ylabel("Attack runs"); plt.legend()
plt.title("Detection latency")
plt.tight_layout(); plt.savefig(os.path.join(RESULTS_DIR, "fig2_latency_hist.png"), dpi=150); plt.close()

snd = ipc.Sender()
ev = watchdog.heartbeats(snd, 0, 10.4) + watchdog.heartbeats(snd, 20, 32)
_, tl = watchdog.run_mcu(ev, 32)
num = {"BOOT": 0, "HEALTHY": 1, "ALERT": 2, "COMM_FAULT": 3, "RECOVERY": 4}
plt.figure(figsize=(7, 3))
plt.step([t for t, s in tl], [num[s] for t, s in tl], "k-", where="post")
plt.axvline(10.4, color="k", ls="--"); plt.axvline(20, color="k", ls=":")
plt.yticks(range(5), list(num)); plt.xlabel("Time (s)")
plt.title("STM32 watchdog: capture crash at 10.4 s, heartbeats resume at 20 s")
plt.tight_layout(); plt.savefig(os.path.join(RESULTS_DIR, "fig3_watchdog_states.png"), dpi=150); plt.close()

plt.figure(figsize=(6, 3.5))
wbar = 0.25
for i, (m, h) in enumerate([("rules", "//"), ("ml", ".."), ("hybrid", "xx")]):
    plt.bar(np.arange(3) + i * wbar, [results[m]["recall"], results[m]["precision"], 1 - results[m]["far"]],
            wbar, fill=False, edgecolor="k", hatch=h, label=m)
plt.xticks(np.arange(3) + wbar, ["Recall", "Precision", "1 - false-alarm rate"]); plt.ylim(0, 1.05)
plt.legend(); plt.title("Rules vs ML vs hybrid")
plt.tight_layout(); plt.savefig(os.path.join(RESULTS_DIR, "fig4_mode_comparison.png"), dpi=150); plt.close()
print("\nDone. See ./results")
