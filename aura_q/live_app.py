"""Command-line entry point for the live system (ESP32 + laptop).

Commands
  python live_app.py ports                                  list the COM ports (find your ESP32)
  python live_app.py learn --port COM5 --seconds 180 [--ml] learn the trusted network (clean network only!)
  python live_app.py run   --port COM5                      detect, dashboard on http://127.0.0.1:5000
  python live_app.py record --port COM5 --out demo.txt --seconds 300    save raw sensor lines
  python live_app.py run   --replay demo.txt [--speed 1]    run the same analysis from a recording

Use --replay for the presentation if the hardware misbehaves: the software path is identical.
"""
import argparse, os, sys, threading, time
import ipc
from config import *
import baseline
import live_engine as LE
import sensor_link as SL


def make_link(args, record=None):
    if getattr(args, "replay", None):
        return SL.ReplayLink(args.replay, speed=args.speed, loop=True)
    if not args.port:
        sys.exit("give --port COMx (see: python live_app.py ports) or --replay FILE")
    return SL.SerialLink(args.port, record_path=record)


def wait_for_data(link, t_needed, label):
    """Wait until the sensor clock has advanced by t_needed seconds since the first beacon."""
    print("Waiting for beacons from the ESP32 (give it a few seconds after plugging in) ...")
    while link.first_t is None:
        time.sleep(0.5)
    t0 = link.first_t
    last = -1
    while link.esp_clock - t0 < t_needed:
        done = int(link.esp_clock - t0)
        if done // 10 != last:
            last = done // 10
            print(f"  {label}: {done}/{int(t_needed)} s  ({link.packets} frames heard)")
        time.sleep(0.5)
    return t0


def cmd_ports(_):
    from serial.tools import list_ports
    ports = list(list_ports.comports())
    if not ports:
        print("No serial ports found. Install the CH340 driver if the board is a DevKit V1 with a CH340 chip.")
    for p in ports:
        print(f"{p.device:10s} {p.description}")


def cmd_learn(args):
    link = make_link(args, record=args.record)
    t0 = wait_for_data(link, args.seconds, "learning")
    beacons = LE.shifted([b for b in link.beacons_since(t0)], t0)
    deauths = LE.shifted([d for d in link.deauths_since(t0)], t0)
    base, ml = LE.learn_baseline(beacons, deauths, duration=args.seconds, use_ml=args.ml)
    baseline.save(base, LIVE_BASELINE)
    if ml is not None:
        import joblib
        joblib.dump(ml, ML_MODEL_PATH)
    print(f"\nLearned {len(base['aps'])} trusted access points -> {LIVE_BASELINE}")
    for b, p in sorted(base["aps"].items(), key=lambda kv: kv[1]["ssid"]):
        print(f"  {p['ssid']:<20s} {b}  {p['rssi_mean']:6.1f} dBm  {','.join(p['security'])}")
    print("Check this list. Anything not on it will be reported as unverified or suspicious.")
    if hasattr(link, "close"):
        link.close()


def cmd_record(args):
    link = make_link(args, record=args.out)
    print(f"Recording raw sensor lines to {args.out} for {args.seconds} s ...")
    t0 = time.monotonic()
    while time.monotonic() - t0 < args.seconds:
        time.sleep(1)
    print(f"Done: {link.packets} frames saved.")
    if hasattr(link, "close"):
        link.close()


def cmd_run(args):
    if not os.path.exists(LIVE_BASELINE):
        sys.exit("No baseline yet. First run:  python live_app.py learn --port COMx --seconds 180")
    base = baseline.load(LIVE_BASELINE)
    ml = None
    if args.ml and os.path.exists(ML_MODEL_PATH):
        import joblib
        ml = joblib.load(ML_MODEL_PATH)
    link = make_link(args)
    engine = LE.LiveEngine(link, base, ml=ml, mode=("hybrid" if ml is not None else "rules"))
    engine.on_alert = lambda score, n: link.send(ipc.T_ALERT, bytes([min(score, 255), min(n, 255), 0, 0]))

    if not args.no_dashboard:
        import dashboard
        app = dashboard.create_app(lambda: engine.state)
        threading.Thread(target=lambda: app.run(host="127.0.0.1", port=args.dashboard_port,
                                                debug=False, use_reloader=False),
                         daemon=True).start()
        print(f"Dashboard: http://127.0.0.1:{args.dashboard_port}   (Ctrl+C to stop)")

    last_hb = last_step = 0.0
    while True:
        now = time.monotonic()
        healthy = True
        if now - last_step >= LIVE_STEP_S:
            last_step = now
            try:
                st = engine.step()
                print(f"[{time.strftime('%H:%M:%S')}] {st['overall']:<12s} {st['headline'][:110]}")
            except Exception as exc:                         # analysis failed: stop the heartbeat
                healthy = False
                print(f"ANALYSIS FAILED: {exc!r} - heartbeat stopped, the ESP32 will show a fault")
        # The heartbeat is sent from the analysis loop on purpose: if the analysis hangs or
        # crashes, the heartbeat stops and the ESP32 declares a communication fault after 3 s.
        if healthy and now - last_hb >= HB_PERIOD:
            last_hb = now
            link.send(ipc.T_HEARTBEAT)
        time.sleep(0.05)


def main():
    ap = argparse.ArgumentParser(description="AURA-Q live system")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("ports")
    for name in ["learn", "record", "run"]:
        p = sub.add_parser(name)
        p.add_argument("--port", help="serial port, e.g. COM5")
        p.add_argument("--replay", help="recorded file to play back instead of a board")
        p.add_argument("--speed", type=float, default=1.0)
    sub.choices["learn"].add_argument("--seconds", type=int, default=180)
    sub.choices["learn"].add_argument("--ml", action="store_true", help="also train the anomaly model")
    sub.choices["learn"].add_argument("--record", help="also save the raw lines to this file")
    sub.choices["record"].add_argument("--out", default="session.txt")
    sub.choices["record"].add_argument("--seconds", type=int, default=300)
    sub.choices["run"].add_argument("--ml", action="store_true", help="use the anomaly model if it was learned")
    sub.choices["run"].add_argument("--no-dashboard", action="store_true")
    sub.choices["run"].add_argument("--dashboard-port", type=int, default=5000)
    args = ap.parse_args()
    {"ports": cmd_ports, "learn": cmd_learn, "record": cmd_record, "run": cmd_run}[args.cmd](args)


if __name__ == "__main__":
    main()
