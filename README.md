# AURA-Q: Rogue Access Point and Evil-Twin Detector

Passive Wi-Fi monitor that tells apart a trusted access point from a rogue one or an evil twin
(an impostor that copies a trusted network name and MAC address). Built for Windows with an
ESP32 DevKit V1 as the sensor. The same code runs on the Arduino UNO Q later.

Defensive use only. Test it on networks you own, or with written permission.

## What is in this folder

| Part | Files | Needs hardware? |
|---|---|---|
| Simulation: proves the algorithm on synthetic Wi-Fi sessions | `run_all.py`, `generator.py` | No |
| Live system: ESP32 sensor + laptop analysis + dashboard | `live_app.py`, `sensor_link.py`, `live_engine.py`, `dashboard.py` | ESP32 (or a recording) |
| ESP32 firmware | `esp32/aura_sensor/aura_sensor.ino`, `esp32/aura_sensor/aura_protocol.h` | ESP32 |
| Tests | `selftest.py`, `esp32/host_tests/test_protocol.c` | No |

Every file is explained in `docs/FILES_EXPLAINED.md`.

## 1. Install Python (once)

1. Install Python 3.11 or 3.12 from python.org. Tick "Add python.exe to PATH".
2. Open a terminal in this folder (File Explorer, click the address bar, type `cmd`, press Enter) and run:

```
py -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Check the software (no hardware needed)

```
python selftest.py
python run_all.py 30
```

`selftest.py` should end with `ALL SELF-TESTS PASSED`. `run_all.py` takes a few minutes and writes
`results\summary.md` and the four figures in `results\`.

## 3. Flash the ESP32 (once)

1. Install the Arduino IDE 2.x from arduino.cc.
2. Tools → Board → Boards Manager, search **esp32**, install **esp32 by Espressif Systems** (version 2.0.17 or 3.x).
3. Plug the DevKit V1 into USB. Tools → Board → **ESP32 Dev Module**.
   Tools → Port → the new COM port (for example COM5).
4. If Windows shows no COM port, install the driver for your board: **CH340** (most DevKit V1 boards)
   or **CP2102** (some others). Then unplug and replug.
5. Open `esp32\aura_sensor\aura_sensor.ino`. Keep `aura_protocol.h` in the same folder.
6. Click Upload (arrow button). If the upload stops at "Connecting...", hold the **BOOT** button on the
   board while it connects, then release.
7. Open Tools → Serial Monitor, set **921600** baud. You should see `# AURA-Q sensor started`
   and then lines beginning with `B|` (beacons heard) and `S|` (status every 2 s).

## 4. Find your COM port

```
python live_app.py ports
```

## 5. Learn your trusted network (once per place)

Stand near your trusted access point, with only your own networks around. Run for 3 minutes:

```
python live_app.py learn --port COM5 --seconds 180
```

Check the list it prints. Every access point on it is trusted. Anything else will be reported.
Add `--ml` to also train the optional anomaly model.

## 6. Run the detector

```
python live_app.py run --port COM5
```

Open **http://127.0.0.1:5000** in your browser. Stop with Ctrl+C.

The alert log is written to `data\alerts.log`.

## 7. Presentation without hardware (safety net)

If the board misbehaves tomorrow, use recordings instead. The analysis code is identical.

```
python demo_tools.py
python live_app.py learn --replay data\demo_learn.txt --speed 25 --seconds 120
python live_app.py run   --replay data\demo_attack.txt --speed 1
```

`demo_attack.txt` has an evil twin switched on at 60 seconds. With `--speed 1` you see the real timing.

To record your own session for the demo, run `python live_app.py record --port COM5 --out my_demo.txt --seconds 300`,
then replay it with `--replay my_demo.txt`.

## Demo script for the presentation (about 3 minutes)

1. Show the simulation results (`results\summary.md`, figure 1, the validation table).
2. Show the dashboard with the ESP32 running: trusted networks shown as KNOWN.
3. Turn on a phone hotspot and name it exactly like one of your learned networks. The dashboard should
   flag it as SUSPICIOUS with the reasons listed (BSSID not on the list, security or IE different, RSSI jump).
4. Press Ctrl+C in the run window. The ESP32 LED switches to the triple-flash fault pattern and the buzzer
   sounds, within 3 seconds. This is the watchdog: a stopped analysis is never mistaken for a safe network.

## Honest limits (say these yourself, judges respect it)

* The ESP32 only hears 2.4 GHz (channels 1, 6 and 11 in this build). The PDF also asks for 5 GHz; that needs a different radio.
* It hops between channels, so it hears each access point only part of the time. That is why the live window is 20 s, not 10 s.
* The simulation assumes every access point is heard all the time, which is optimistic. Its results show that the algorithm works, not that the radio is perfect.
* The ESP32 is a sensor and a stand-in for the STM32 watchdog. The UNO Q's STM32 and the 5G part are next steps.
* Dashboard independence (validation test 7) needs the board itself and is marked N/A in the simulation.
* In the simulation, machine learning did not add detections beyond the rules (hybrid equals rules). Say so; the rules carry the result.

## Troubleshooting

| Problem | Fix |
|---|---|
| `No module named serial` | Run `venv\Scripts\activate` first, then `pip install -r requirements.txt` |
| COM port missing | Install the CH340 or CP2102 driver; try another USB cable (some are charge-only) |
| Dashboard shows SYSTEM_FAULT "no data" | Check the COM port number, close the Arduino Serial Monitor (it blocks the port) |
| Lots of UNVERIFIED after learning | Learn again for longer (`--seconds 300`) in a quieter place |
| Board keeps resetting | Use a data-capable USB cable; the code already keeps DTR low on open |
| `learn --ml` then `run --ml` errors | Delete `data\ml_model.joblib` and learn again with `--ml` |
