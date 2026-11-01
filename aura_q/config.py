"""All tunable numbers in one place.

Change a value here, re-run the program, and compare the results.
Sections: simulation timing, live (ESP32) timing, detection thresholds,
STM32 watchdog timing, USB link, and file locations.
"""
import os

# ---- simulation timing (run_all.py) ----
DURATION = 120.0          # seconds per simulated session
ATTACK_START = 60.0       # attacker switches on at t = 60 s
BEACON_INTERVAL = 0.1024  # 102.4 ms, the standard 802.11 beacon interval
WINDOW_S = 10.0           # simulation analysis window (PDF says 10-30 s)
STEP_S = 2.0              # window slides forward every 2 s

# ---- live timing (ESP32 + laptop, live_app.py) ----
LIVE_WINDOW_S = 20.0      # longer than the sim: the ESP32 hops channels, so it hears each AP only part of the time
LIVE_STEP_S = 2.0         # the analysis runs every 2 s
LIVE_MODE = "hybrid"      # 'rules' | 'ml' | 'hybrid'
SENSOR_TIMEOUT_S = 3.0    # no data from the ESP32 for this long -> SYSTEM FAULT (PDF: 3 s)

# ---- rules engine thresholds (PDF sections 4.2 and 4.3) ----
MIN_SAMPLES = 30          # fewer samples than this -> UNVERIFIED
RSSI_DEV_DB = 12.0        # mean RSSI shift from the baseline that counts as a clue
RSSI_STD_MAX = 8.0        # PDF: RSSI std-dev above 8 dB is a clue
JITTER_MS_MAX = 3.0       # beacon timing jitter (weak clue only)
SEQ_JUMP_MAX = 0.25       # fraction of abnormal sequence-number steps
DEAUTH_RATE_MAX = 5.0     # deauthentication frames per second
PROTECTED_SSIDS = {"IIITB-Campus"}   # your own protected network name(s)

# ---- STM32 watchdog timing (PDF section 4.4) ----
# The Python simulation (watchdog.py) and the ESP32 firmware (aura_protocol.h) use the same numbers.
HB_PERIOD = 1.0           # the laptop sends a heartbeat every 1.0 s
WD_TIMEOUT = 3.0          # fault if no valid heartbeat for 3.0 s
BAD_THRESH = 3            # this many bad frames ...
BAD_WINDOW = 3.0          # ... within this many seconds -> COMM_FAULT
RECOVERY_CYCLES = 5       # valid heartbeats needed before HEALTHY again
ALERT_HOLD = 5.0          # stay in ALERT this long after the last alert frame
UART_BAUD = 115200        # PDF's Linux-to-MCU link speed (used for frame timing in the simulation)

# ---- ESP32 USB link (laptop <-> ESP32 DevKit V1) ----
SERIAL_BAUD = 921600      # must equal SENSOR_BAUD in esp32/aura_sensor/aura_sensor.ino

# ---- file locations ----
RESULTS_DIR = "results"
DATA_DIR = "data"
SIM_BASELINE = os.path.join(RESULTS_DIR, "baseline.db")
LIVE_BASELINE = os.path.join(DATA_DIR, "baseline.db")
ML_MODEL_PATH = os.path.join(DATA_DIR, "ml_model.joblib")
ALERT_LOG = os.path.join(DATA_DIR, "alerts.log")
