# AURA-Q: what every file does, and how

This document explains each file in the project: its job, how it works, and what it
depends on. It is written so that you can answer questions about any line during the
presentation.

The project has three layers:

1. **Algorithm** (pure Python, simulated data): decides whether a network is trusted or suspicious.
2. **Live system** (Python on the laptop plus an ESP32 sensor): the same algorithm fed by real beacons.
3. **Watchdog** (C on the ESP32, and Python in the simulation): supervises the system and raises a
   visible fault if the analysis stops.

---

## The big picture in plain words

A Wi-Fi access point announces itself about ten times a second with a "beacon": its name (SSID),
its hardware address (BSSID), its channel, its security type, and its capabilities. An attacker
can copy the name and the hardware address, but not everything else exactly. The system listens
to those beacons and asks several questions:

* Is this hardware address on the trusted list?
* Has the security mode or capability fingerprint changed?
* Has the signal strength jumped, or become very unstable?
* Are the sequence numbers jumping around (two transmitters talking at once)?
* Is somebody sending "disconnect" frames (deauthentication) at a high rate?

Each "yes" is a **clue**. Strong clues are hard evidence. Weak clues are supporting evidence only.
A network is marked **SUSPICIOUS** only with at least two clues and at least one strong one. This
avoids false alarms from a person walking past a router. Every verdict lists its reasons, so the
operator can check them.

---

## Files you uploaded, and what changed

Your uploaded `rules.py`, `generator.py` and `run_all.py` came from the first version of the
simulation. The zip you uploaded contained the complete set of modules, and the three loose files
match it. The version in this project is the cleaned one. Changes:

| File | Change | Why |
|---|---|---|
| `rules.py` | A protected network name (`PROTECTED_SSIDS`) is now used. A rogue with a campus name and no learned profile is reported as unverified with the reason, not silently ignored. | The config value existed but nothing read it. |
| `features.py` | Sequence-number checking only compares frames that arrived less than 0.25 s apart. `featurize()` takes the window size as a parameter. | The ESP32 hops channels, so frames far apart in time say nothing about sequence collisions. Live analysis needs a 20 s window. |
| `baseline.py` | Paths are parameters. The database table is rebuilt on save. Folders are created when needed. | The live and simulated baselines are stored in different places. |
| `pipeline.py` | `classify_keys()` added: classifies every network in one window. `classify_windows()` uses it. | The live dashboard needs one status per network, not only the worst one. |
| `run_all.py` | Dead code removed (an unused variable, a no-op check). Uses the shared paths. | Clarity. Results are unchanged. |
| `config.py` | Live timing, serial baud, file paths and the sensor-timeout value added. | One place for every number. |

The simulation results after the changes are the same as before (see section "Results" below).

---

## Top level

### `config.py`
**Job:** every tunable number in one place.
* Simulation timing: `DURATION` (120 s per session), `ATTACK_START` (60 s), `WINDOW_S` (10 s analysis window), `STEP_S` (2 s).
* Live timing: `LIVE_WINDOW_S` (20 s), `LIVE_STEP_S`, `SENSOR_TIMEOUT_S` (3 s without data means a fault).
* Detection thresholds (from the PDF): `MIN_SAMPLES` = 30, `RSSI_DEV_DB` = 12 dB, `RSSI_STD_MAX` = 8 dB,
  `JITTER_MS_MAX`, `SEQ_JUMP_MAX` = 0.25, `DEAUTH_RATE_MAX` = 5 frames per second.
* `PROTECTED_SSIDS`: the network names you want guarded (set this to your own network name).
* Watchdog timing: heartbeat every 1 s, timeout 3 s, bad-frame threshold 3 in 3 s, 5 valid frames to recover, alert hold 5 s.
  These numbers must match `aura_protocol.h` on the ESP32.
* `SERIAL_BAUD` = 921600 (must match the sketch).
* File locations for the baseline database, the ML model and the alert log.

**Why it matters:** if a judge asks "why 3 seconds?", the answer is in this file and in the PDF.

### `generator.py` (from your upload, unchanged)
**Job:** creates a fake Wi-Fi world so the algorithm can be tested without radio hardware.
* Defines five trusted access points (two campus, one lab guest, two mesh nodes).
* `make_stream()` makes the beacons of one transmitter: a steady 102.4 ms rhythm, random jitter, random
  lost beacons, slow signal fading, sequence numbers, and optional "a person walks past" dips.
* `build(kind, seed)` makes one 120-second session of a given scenario:
  `normal` (clean), `obstacle` (person walks past), `low_sample` (weak signal), `mesh` (a trusted node
  changes channel), `rogue_ap` (an unknown router with a campus name), `evil_twin` (a copy with the same
  BSSID and +5 to +25 dB power), `stealth_twin` (a careful copy with the same channel, security and IE,
  only +2 to +6 dB stronger).
* It returns the streams, the deauthentication bursts, and the ground truth (when the attack started), so
  the results can be scored.

**Honest note:** the generator decides what attacks look like. The detection numbers show the algorithm
handles these attack models, not that every real attacker behaves this way.

### `features.py`
**Job:** turns raw beacons into numbers for each sliding window.
* `extract_window()` looks at one time window (for example 10 seconds, 115 beacons) and, for each
  (SSID, BSSID) pair, computes:
  * RSSI statistics: count, mean, median, minimum, maximum, standard deviation, and change since the last window.
  * `jitter_ms`: how irregular the beacon spacing is, after allowing for lost beacons.
  * `seq_jump`: the fraction of sequence-number steps that are not small forward steps.
    Two transmitters on one channel produce these, because each keeps its own counter.
  * `deauth_rate`: deauthentication frames per second aimed at that BSSID.
  * The sets of channels, security modes and IE fingerprints seen.
* `featurize()` slides that window across a whole session in 2-second steps.

### `baseline.py`
**Job:** learns what "normal" looks like and stores it.
* `learn()` runs `featurize()` over clean sessions and records, for each BSSID: its SSID, its average RSSI, and the
  channels, security modes and IE fingerprints it used. It also builds a summary per SSID (the strongest
  approved signal and the set of expected security modes).
* `save()` and `load()` store and read this as a SQLite database file (`baseline.db`). In the PDF this database
  lives on the board's eMMC memory. Here it is an ordinary file, which is the same idea.

### `rules.py`
**Job:** the explainable decision engine. This is the heart of the system.
* `classify(key, features, baseline)` runs in this order:
  1. Fewer than 30 samples: UNVERIFIED (not enough evidence yet). This guards against overconfident alarms.
  2. BSSID not in the trusted list:
     * If the SSID is also unknown and not protected: UNVERIFIED ("new network").
     * If the SSID is trusted or protected: a strong clue ("known name, unverified hardware address").
       A signal much stronger than the approved AP adds another strong clue.
  3. BSSID trusted: the mean RSSI is compared with its own baseline. A shift above 12 dB is a strong clue.
  4. Security mode differs from the baseline: strong clue.
  5. IE capability fingerprint differs: strong clue.
  6. Channel not in the baseline: weak clue. RSSI standard deviation above 8 dB: weak clue. Timing jitter above 3 ms: weak clue.
  7. Sequence-number discontinuities above 25%: strong clue. Deauthentication above 5 per second: strong clue.
* The decision: at least two clues with at least one strong one gives **SUSPICIOUS**. One or more weak clues
  give **UNVERIFIED**. No clues give **KNOWN**. A risk score (0-100) adds the weights of the clues.

**Why this design:** each step is a simple rule a human can read. There is no black box in the decision,
so every alert can be explained, which the PDF calls "zero alert fatigue".

### `ml.py` (from your upload, unchanged)
**Job:** an optional anomaly detector, the stand-in for the Adreno GPU stage in the PDF.
* Uses an Isolation Forest (scikit-learn). It is trained only on normal windows, so it learns what normal
  looks like and flags anything unusual.
* `flags()` returns True for windows that look unusual.

### `pipeline.py`
**Job:** joins the rules and the optional ML model.
* `classify_keys()` classifies every network in one window with the chosen mode:
  * `rules`: rules only (the fallback if the ML part is off or broken).
  * `ml`: the ML model alone (only for comparison).
  * `hybrid`: the rules decide; ML may only confirm a window that already has a strong clue. This keeps ML from
    creating alerts on its own.
* `classify_windows()` gives the worst status per window (used by the simulation).
* `format_alert()` writes one readable line per alert.

**Finding from the simulation:** `hybrid` gives the same numbers as `rules`. The ML model on its own
has more false alarms (1.2% of windows). So in this project the rules carry the result. Say this openly
if asked; it is a better answer than claiming ML improves detection.

### `ipc.py` (from your upload, unchanged)
**Job:** the binary message format between the laptop and the watchdog board.
* Frame: `[0xAA | version | type | sequence (2 bytes) | length | payload (up to 32 bytes) | CRC16 (2 bytes)]`.
* `build_frame()` builds one. `parse_frame()` checks it in this order: start byte, version, length limit,
  length match, known type, CRC. Any failure means the frame is rejected.
* `crc16_ccitt()` is the checksum (CRC-16/CCITT). The C version on the ESP32 gives the same bytes:
  `selftest.py` checks this with the heartbeat frame `AA0101000100FED8`.

### `watchdog.py` (from your upload, unchanged)
**Job:** the Python copy of the STM32 safety state machine, used by the simulation.
* States: BOOT → HEALTHY → ALERT → COMM_FAULT → RECOVERY → HEALTHY.
* HEALTHY: valid heartbeat within 3 s. ALERT: an alert frame arrived (held for 5 s). COMM_FAULT: no heartbeat for
  3 s, or 3 bad frames within 3 s. RECOVERY: needs 5 valid frames before returning to HEALTHY, so flapping
  links do not look healthy.
* `heartbeats()` creates the heartbeat schedule. `run_mcu()` replays events and records the state over time.

### `run_all.py`
**Job:** runs the complete simulation and prints, saves and plots everything.
1. Learns the baseline from 20 clean sessions, saves it to SQLite, reloads it to prove the round trip.
2. Trains the ML model on normal windows (different random seeds from the test sessions, so there is no cheating).
3. Runs 30 sessions per scenario (210 in total), in three modes: rules, ML, hybrid.
4. Scores every window against the ground truth: accuracy, recall (how many attacks were caught), precision
   (how many alarms were real), false-alarm rate, and detection latency (seconds from attack start to the first SUSPICIOUS).
5. Measures end-to-end timing: attack → alert frame → watchdog ALERT state.
6. Watchdog tests: 200 random crash times (fault delay), 2000 random bit-flip corruptions (rejected), special frames.
7. Runs the nine validation tests from PDF section 5.2 and marks each PASS, FAIL or N/A.
8. Writes `results/summary.md`, `metrics.csv`, `validation.csv`, `baseline.db`, and four figures.

**Read the results carefully:** the numbers above are for simulated attacks. Test 7 (dashboard independence)
can only be checked on the board.

### `demo_tools.py` (new)
**Job:** creates text recordings in the exact format the ESP32 prints.
* `sim_to_lines()` converts simulated streams into `B|...` and `D|...` lines. It deliberately starts the sensor
  clock at 4200 s, so the 32-bit microsecond counter wraps during the demo and the code is tested on that case.
* `make_demo_files()` writes `data/demo_learn.txt` (clean network) and `data/demo_attack.txt` (evil twin at 60 s).
  These let you run the complete live path with no hardware.

### `selftest.py` (new)
**Job:** checks the parts that the simulation does not cover.
1. The line parser: good lines, malformed lines, wrong number of fields.
2. The golden heartbeat frame, which must match the C test.
3. Learning a baseline from text lines, and the clock wrap.
4. The live engine on simulated sessions: a clean network must never be flagged; the evil twin and the rogue AP
   must be flagged from the attack onset (not before it, and within 15 s after it); no data means SYSTEM_FAULT.
5. The USB path, using a fake COM port: correct baud, DTR low on open (so the board does not reset),
   lines turned into records, frames written with the right length.

---

## Live system (laptop side)

### `sensor_link.py`
**Job:** the connection to the ESP32, and two stand-ins.
* **Text protocol from the ESP32** (one line each):
  * `B|channel|rssi|sequence|timestamp_us|BSSID|security|IE_hash|SSID`: a beacon or probe response.
  * `D|channel|timestamp_us|BSSID`: a deauthentication frame.
  * `S|uptime_ms|state|drops|rejects`: a status line every 2 s.
  * Lines starting with `#` are debug text and are ignored.
* `parse_line()` turns one line into a dictionary, or returns None if it is malformed (it never crashes on bad input).
* `_Clock` turns the ESP32's 32-bit microsecond counter, which wraps every 71 minutes, into continuous seconds.
* `LinkBase` keeps the last 180 seconds of beacons and deauthentications, thread-safely, and tracks
  `esp_clock` (the sensor's time) and `silence_s()` (how long since the last line; used for the 3 s sensor fault).
* `SerialLink` opens the COM port at 921600 baud with DTR and RTS low, which stops a DevKit board from resetting
  when the port opens. A background thread reads lines. `send()` writes CRC frames (heartbeat, alert).
  Optional `record_path` saves the raw lines to a file.
* `ReplayLink` plays a recording back at real speed (or faster). When the file loops, it shifts the timestamps
  forward, so time keeps moving forward. (A bug in an earlier version treated the restart as a time jump; the
  fix is verified by the learn test.)
* `MemoryLink` has no thread and no device. The self-test feeds it lines directly.

### `live_engine.py`
**Job:** runs the algorithm on live data, one step every 2 seconds.
* `to_streams()` groups the beacons by (SSID, BSSID, channel, security, IE) into the stream format that
  `features.py` expects. `to_deauths()` does the same for deauthentication frames.
* `learn_baseline()` learns the trusted baseline from a recording of a clean network, with the 20 s window.
  It can also train the ML model.
* `LiveEngine.step()`:
  1. If the sensor has been silent for more than 3 s: **SYSTEM_FAULT** ("no data from the ESP32").
  2. If less than one full window has been collected: **WAITING**.
  3. Otherwise: take the last 20 s, extract features, classify every network, and sort them by severity.
  4. If any network is SUSPICIOUS: write the alert to `data/alerts.log` (at most once per 30 s per network),
     and ask for an alert frame to be sent to the ESP32, which then shows the alarm pattern.
  5. Publish the state for the dashboard: overall status, a one-line headline, a table of all networks, the sensor
     health, and the recent alerts.

### `dashboard.py`
**Job:** the local web page at http://127.0.0.1:5000.
* A Flask server with two routes: `/` (the page) and `/api/state` (the JSON state).
* The page refreshes once per second and draws the status banner (colour per status), the network table,
  the sensor panel and the alert log.
* **Security detail:** every network name is inserted with `textContent`, never `innerHTML`. A hostile network
  name therefore appears as plain text and cannot run code in the page. This is the XSS protection from the PDF.
* It only reads state. If the dashboard crashes, detection continues (validation test 7 in the PDF).

### `live_app.py`
**Job:** the command-line entry point. Commands:
* `ports`: lists COM ports, so you can find the ESP32.
* `learn --port COMx --seconds 180 [--ml]`: records a clean network and saves the baseline.
  It prints the learned list so you can check it.
* `record --port COMx --out file.txt --seconds 300`: saves raw lines for later replay.
* `run --port COMx` or `run --replay file.txt`: the main loop. Every second it sends a heartbeat to the ESP32;
  every 2 seconds it runs one analysis step. **The heartbeat is sent from the analysis loop on purpose**: if the
  analysis hangs or crashes, the heartbeats stop, and the ESP32 declares a communication fault after 3 seconds.
  If one analysis step throws an exception, the heartbeat is stopped deliberately, for the same reason.

---

## ESP32 firmware

### `esp32/aura_sensor/aura_protocol.h`
**Job:** the protocol and the watchdog state machine in plain C, with no Arduino code.
* `aura_crc16()`, `aura_build()`, `aura_parse()`: the same frame format and checks as `ipc.py`.
* `wd_on_bytes()` and `wd_tick()`: the same state machine as `watchdog.py`, including the same numbers.
* Keeping this separate from the sketch means it can be tested on a PC: `esp32/host_tests/test_protocol.c`
  runs 18 checks, including a timeline test (fault exactly 3 s after the last heartbeat, recovery after five
  valid frames) and 2000 random bit-flip tests.

### `esp32/aura_sensor/aura_sensor.ino`
**Job:** the firmware that runs on the ESP32 DevKit V1.
* **Sniffer:** promiscuous mode, management frames only (beacons, probe responses, deauthentication). The
  board never transmits Wi-Fi and never connects to a network. It hops across channels 1, 6 and 11 every 300 ms.
* **Callback:** parses each beacon: SSID, channel from the DS parameter, security (open, WEP, WPA, WPA2 Personal,
  WPA2 Enterprise, WPA3 from the RSN suite type), and an IE fingerprint (the order and lengths of the information
  elements, plus the HT and VHT capability contents). It copies the record into a queue and returns quickly.
* **Output:** the main loop prints one text line per record, at most 40 per loop, so the loop stays responsive.
* **Watchdog:** receives CRC frames from the laptop byte by byte, resynchronises on the start byte, and calls the same
  state machine as the host tests.
* **Outputs:** LED on GPIO2 (the onboard LED) with a different pattern per state:
  steady on at boot, short heartbeat blink in HEALTHY, fast blink with buzzer in ALERT, triple flash with buzzer in
  COMM_FAULT, and a slow blink in RECOVERY. The buzzer is an optional active buzzer on GPIO4.
* **Status line** every 2 seconds, so the laptop knows the board's state.

**Limits of the firmware:** the ESP32's radio is 2.4 GHz only. Frames that arrive while the board is on another
channel are not seen. The code was checked for syntax against stand-in headers and the protocol part was tested
on a PC; it has not been compiled with the real Arduino ESP32 core in this environment. If the compile shows an
error, it will most likely be a version difference in the Wi-Fi API; the README troubleshooting table covers the usual causes.

### `esp32/host_tests/test_protocol.c`
**Job:** tests `aura_protocol.h` on a PC, with no board.
* Compile and run: `gcc -std=c99 -Wall -Wextra -I../aura_sensor test_protocol.c -o test_protocol` then `./test_protocol`.
* Prints a golden heartbeat frame that `selftest.py` checks as well, so the two sides are known to agree.

---

## Support files

* `requirements.txt`: numpy, scikit-learn, matplotlib (simulation and ML), pyserial (USB), flask (dashboard), joblib (saving the ML model).
* `README.md`: step-by-step for Windows, flashing, learning, running, the presentation script, and the honest limits.
* `results/`: generated by `run_all.py`. `summary.md` is the full report; `metrics.csv` and `validation.csv` hold the tables;
  `baseline.db` is the simulated baseline; figures 1 to 4 show the evil-twin timeline, latency histogram, watchdog states and mode comparison.
* `data/`: `demo_learn.txt` and `demo_attack.txt` (recordings), and at run time `baseline.db` (your learned network), `ml_model.joblib`
  (optional) and `alerts.log` (forensic log).

---

## Results (simulation, 30 sessions per scenario, 120 s each)

| Scenario | Runs with a SUSPICIOUS verdict | Median time to alarm |
|---|---|---|
| Normal, obstacle, weak signal, mesh channel change | 0 of 120 | - |
| Rogue access point | 30 of 30 | 4.0 s |
| Evil twin (copied BSSID, stronger) | 30 of 30 | 2.0 s |
| Stealth twin (copies channel, security and IE) | 22 of 30 | 2.0 s |

* Overall, rules: recall 91.1%, precision 99.4%, false-alarm rate 0.15% of windows.
* Attack onset to MCU ALERT state: median 2.05 s, 95th percentile 4.05 s (compute time not modelled).
* Watchdog: capture crash detected within 3.00 s in all 200 trials.
* IPC: 2000 of 2000 corrupted frames rejected.

The eight stealth twins that were missed are the honest weak point: the algorithm relies on
security, IE and sequence clues, and a careful attacker who copies all three is harder to catch. Say so in the presentation.
