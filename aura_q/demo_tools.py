"""Demo helpers.

sim_to_lines()     turns simulated Wi-Fi sessions into the exact text lines the ESP32 prints.
                   Used by selftest.py and to build demo recordings.
make_demo_files()  writes two recordings you can replay with no hardware:
                     demo_learn.txt  - a clean network (for `learn --replay`)
                     demo_attack.txt - the same network with an evil twin switched on at 60 s
    python demo_tools.py
"""
import os, zlib
import generator as G
from config import DURATION, DATA_DIR

BOOT_OFFSET = 4200.0      # simulated sensor clock: starts at 4200 s, so the 32-bit counter wraps during the run


def sim_to_lines(streams, deauths, boot_offset=BOOT_OFFSET):
    events = []
    for s in streams:
        ssid = s["ssid"].replace("|", "_")
        ie = str(zlib.crc32(s["ie"].encode()))
        for t, r, q in zip(s["t"], s["rssi"], s["seq"]):
            ts = int(round((t + boot_offset) * 1e6)) & 0xFFFFFFFF
            events.append((t, f"B|{s['channel']}|{int(round(r))}|{int(q)}|{ts}|{s['bssid']}|{s['security']}|{ie}|{ssid}\n"))
    for d in deauths:
        for t in d["t"]:
            ts = int(round((t + boot_offset) * 1e6)) & 0xFFFFFFFF
            events.append((t, f"D|6|{ts}|{d['bssid']}\n"))
    events.sort(key=lambda e: e[0])
    return [line for _, line in events]


def make_demo_files(out_dir=DATA_DIR, seed=12345):
    os.makedirs(out_dir, exist_ok=True)
    s, d, _ = G.build("normal", seed)
    with open(os.path.join(out_dir, "demo_learn.txt"), "w", encoding="utf-8") as f:
        f.write("# AURA-Q demo recording: clean network (simulated)\n")
        f.writelines(sim_to_lines(s, d))
    s, d, truth = G.build("evil_twin", seed + 1)
    with open(os.path.join(out_dir, "demo_attack.txt"), "w", encoding="utf-8") as f:
        f.write("# AURA-Q demo recording: evil twin switched on at 60 s (simulated)\n")
        f.writelines(sim_to_lines(s, d))
    return [os.path.join(out_dir, "demo_learn.txt"), os.path.join(out_dir, "demo_attack.txt")]


if __name__ == "__main__":
    for p in make_demo_files():
        print("wrote", p, f"({os.path.getsize(p) // 1024} KB)")
