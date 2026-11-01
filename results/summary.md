Baseline learned for 5 trusted APs (stored in results\baseline.db)
Isolation Forest trained on 33600 benign windows (different seeds from the test set)
Simulated 210 sessions (30 per scenario, 120 s each)

## Overall detection metrics (window level; SUSPICIOUS = positive)
| Mode | Accuracy | Recall | Precision | False-alarm rate | Runs detected | Median latency (s) | 95th pct latency (s) |
|---|---|---|---|---|---|---|---|
| rules | 0.9789 | 0.911 | 0.994 | 0.0015 | 91.1% | 2.0 | 4.0 |
| ml | 0.9392 | 0.771 | 0.947 | 0.0124 | 97.8% | 2.0 | 4.0 |
| hybrid | 0.9789 | 0.911 | 0.994 | 0.0015 | 91.1% | 2.0 | 4.0 |

## Per scenario (hybrid mode)
| Scenario | Runs | Runs with >=1 SUSPICIOUS | Detected after onset | Median latency (s) |
|---|---|---|---|---|
| normal | 30 | 0 | - | - |
| obstacle | 30 | 0 | - | - |
| low_sample | 30 | 0 | - | - |
| mesh | 30 | 0 | - | - |
| rogue_ap | 30 | 30 | 30/30 | 4.0 |
| evil_twin | 30 | 30 | 30/30 | 2.0 |
| stealth_twin | 30 | 22 | 22/30 | 2.0 |

End-to-end attack onset -> MCU ALERT state: median 2.05 s, 95th pct 4.05 s over 82 detected attack runs (UART frame time at 115200 baud = 1.0 ms; compute time not modelled)

Watchdog fault-detection delay after capture crash: mean 2.50 s, max 3.00 s (200 trials)
IPC corruption: 2000/2000 bit-flipped frames rejected; special cases rejected as ['oversized', 'unknown_type']; garbage burst -> COMM_FAULT=True, final state=HEALTHY; reject reasons={'bad_sof': 10}

## Validation tests (PDF section 5.2)
| Test | Pass criterion | Measured | Result |
|---|---|---|---|
| 1 Normal baseline stability | Runs with any SUSPICIOUS <= 5% | 0.0% | PASS |
| 2 Environmental obstacle | Runs with any SUSPICIOUS <= 5% | 0.0% | PASS |
| 3 Evil-twin canary | Detected >= 90% and median latency <= 10 s | 100.0% / 2.0 s | PASS |
| 4 Low-sample guardrail | UNVERIFIED shown, SUSPICIOUS in <= 5% of runs | UNVERIFIED 100%, SUSPICIOUS 0.0% | PASS |
| 5 Capture process crash | COMM_FAULT within 3 s | max 3.00 s | PASS |
| 6 IPC corruption injection | 100% rejected + fault state | 2000/2000, fault=True | PASS |
| 7 Dashboard independence | Alerts continue with Flask stopped | NOT SIMULATED - verify on the board | N/A |
| 8 ML fallback resilience | Rules-only mode still detects >= 80% of evil twins | 100.0% detected with rules only | PASS |
| 9 Legit roaming / mesh | SUSPICIOUS <= 5% and channel change logged | SUSPICIOUS 0.0%, logged 100% | PASS |

Example explainable alert (evil_twin seed 0):
[SUSPICIOUS - Risk Score: 80/100 | Window: 10 s (115 samples)] SSID 'IIITB-Campus', BSSID A4:2B:8C:11:00:01: 802.11 IE capability profile differs from baseline; RSSI std-dev 8.3 dB > 8 dB; beacon timing jitter 36.2 ms; sequence-number discontinuities (35% of steps); deauthentication burst (8 frames/s).
