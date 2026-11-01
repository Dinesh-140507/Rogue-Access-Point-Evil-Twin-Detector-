/*
 * AURA-Q sensor firmware for ESP32 DevKit V1 (ESP32-WROOM-32, 2.4 GHz only).
 *
 * What it does
 *  1. Passive listening: promiscuous mode, management frames only. It never transmits
 *     Wi-Fi frames and never joins a network. It hops across channels 1, 6 and 11.
 *  2. Beacon and deauthentication reports: one text line per frame over USB serial
 *     (format in sensor_link.py). Names, channels, security and IE fingerprints are included.
 *  3. Safety watchdog (stand-in for the STM32U585 in the PDF): it reads CRC-framed heartbeats
 *     and alerts from the laptop, runs the state machine in aura_protocol.h and drives an
 *     LED (GPIO2, onboard) and an optional buzzer (GPIO4). If the laptop stops, the board
 *     shows a fault pattern by itself.
 *
 * Arduino IDE settings: Board "ESP32 Dev Module", Upload speed 921600 (or 115200 if upload fails).
 * Keep aura_protocol.h in the same folder as this file.
 */
#include <Arduino.h>
#include <stdio.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include <string.h>
#include "aura_protocol.h"

#define SENSOR_BAUD 921600          /* must equal SERIAL_BAUD in config.py */
#define LED_PIN 2                   /* onboard LED on DevKit V1 */
#define BUZZER_PIN 4                /* optional active buzzer, + to GPIO4, - to GND */
#define HOP_MS 300                  /* dwell time per channel */
static const uint8_t CHANNELS[3] = {1, 6, 11};

struct Rec {
  uint8_t kind;                     /* 'B' beacon / probe response, 'D' deauthentication */
  uint8_t ch;
  int8_t rssi;
  uint16_t seq;
  uint32_t ts;                      /* microseconds from the Wi-Fi hardware */
  uint8_t bssid[6];
  char sec[16];
  uint32_t ie;                      /* fingerprint of tag order, lengths, HT/VHT capabilities */
  char ssid[33];
};

static QueueHandle_t rxQueue = NULL;
static volatile uint32_t dropCount = 0;
static aura_wd_t wd;
static uint8_t rxBuf[8 + AURA_MAX_PAYLOAD];
static uint8_t rxLen = 0;

/* ---------------------------------------------------------------- beacon parsing helpers */

static uint32_t fnv(uint32_t h, const uint8_t* d, size_t n) {
  for (size_t i = 0; i < n; i++) { h ^= d[i]; h *= 16777619u; }
  return h;
}

/* RSN information element: returns the suite type of the first AKM (1 = 802.1X, 2 = PSK, 8/9 = SAE). */
static uint8_t rsnAkmType(const uint8_t* d, int l) {
  int off = 6;                                   /* version (2) + group cipher (4) */
  if (off + 2 > l) return 0;
  int n = d[off] | (d[off + 1] << 8);            /* pairwise cipher count */
  off += 2 + 4 * n;
  if (off + 2 > l) return 0;
  int m = d[off] | (d[off + 1] << 8);            /* AKM suite count */
  off += 2;
  if (m < 1 || off + 4 > l) return 0;
  return d[off + 3];
}

static void securityOf(bool privacy, bool hasRsn, uint8_t akm, bool hasWpa, char* out, size_t n) {
  const char* s;
  if (hasRsn)       s = (akm == 8 || akm == 9) ? "WPA3-SAE" : (akm == 1 ? "WPA2-Enterprise" : "WPA2-PSK");
  else if (hasWpa)  s = "WPA-PSK";
  else if (privacy) s = "WEP";
  else              s = "Open";
  strncpy(out, s, n - 1);
  out[n - 1] = 0;
}

static void cleanSsid(char* s) {
  for (char* p = s; *p; p++)
    if (*p == '|' || *p == '\r' || *p == '\n' || (uint8_t)*p < 32) *p = '_';
}

/* ---------------------------------------------------------------- promiscuous callback */
/* Runs inside the Wi-Fi task. Keep it short: parse, copy into the queue, return. */
static void snifferCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  (void)type;
  const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
  int len = (int)pkt->rx_ctrl.sig_len - 4;     /* strip the 4-byte FCS */
  if (len < 24) return;
  const uint8_t* f = pkt->payload;
  uint8_t ftype = (f[0] >> 2) & 0x03;
  uint8_t subtype = (f[0] >> 4) & 0x0F;
  if (ftype != 0) return;                      /* management frames only */
  bool isDeauth = (subtype == 12 || subtype == 10);     /* deauthentication, disassociation */
  bool isBeacon = (subtype == 8);       /* beacon, probe response */
  if (!isDeauth && !isBeacon) return;

  Rec r;
  memset(&r, 0, sizeof r);
  r.kind = isDeauth ? 'D' : 'B';
  r.ch = pkt->rx_ctrl.channel;
  r.rssi = pkt->rx_ctrl.rssi;
  r.ts = pkt->rx_ctrl.timestamp;
  memcpy(r.bssid, f + 16, 6);                  /* address 3 = BSSID for beacons and deauths */
  r.seq = (uint16_t)(((f[22] | (f[23] << 8)) >> 4) & 0x0FFF);

  if (isBeacon) {
    if (len < 36) return;
    uint16_t cap = f[34] | (f[35] << 8);
    bool privacy = (cap & 0x0010) != 0;
    const uint8_t* p = f + 36;
    int rem = len - 36;
    bool hasRsn = false, hasWpa = false;
    uint8_t akm = 0;
    uint32_t h = 2166136261u;
    while (rem >= 2) {
      uint8_t id = p[0], l = p[1];
      if (l > rem - 2) break;
      const uint8_t* d = p + 2;
      if (id == 0) {                           /* SSID */
        size_t n = l < 32 ? l : 32;
        memcpy(r.ssid, d, n);
        r.ssid[n] = 0;
      } else if (id == 3 && l == 1) {          /* DS parameter set: channel */
        r.ch = d[0];
      } else if (id == 48) {                   /* RSN (WPA2/WPA3) */
        hasRsn = true;
        akm = rsnAkmType(d, l);
      } else if (id == 221 && l >= 4 && d[0] == 0x00 && d[1] == 0x50 && d[2] == 0xF2 && d[3] == 0x01) {
        hasWpa = true;                         /* WPA1 vendor element */
      }
      h = fnv(h, &id, 1);
      h = fnv(h, &l, 1);
      if (id == 45 || id == 191) h = fnv(h, d, l);   /* HT and VHT capability contents */
      p += 2 + l;
      rem -= 2 + l;
    }
    r.ie = h ^ cap;
    cleanSsid(r.ssid);
    securityOf(privacy, hasRsn, akm, hasWpa, r.sec, sizeof r.sec);
  }
  if (xQueueSend(rxQueue, &r, 0) != pdTRUE) dropCount++;
}

/* ---------------------------------------------------------------- output */

static void printRec(const Rec& r) {
  char mac[18];
  snprintf(mac, sizeof mac, "%02X:%02X:%02X:%02X:%02X:%02X",
           r.bssid[0], r.bssid[1], r.bssid[2], r.bssid[3], r.bssid[4], r.bssid[5]);
  if (r.kind == 'D') {
    Serial.printf("D|%u|%lu|%s\n", (unsigned)r.ch, (unsigned long)r.ts, mac);
  } else {
    Serial.printf("B|%u|%d|%u|%lu|%s|%s|%lu|%s\n", (unsigned)r.ch, (int)r.rssi, (unsigned)r.seq,
                  (unsigned long)r.ts, mac, r.sec, (unsigned long)r.ie, r.ssid);
  }
}

/* ---------------------------------------------------------------- frames from the laptop */

static void handleRx(uint32_t now) {
  while (Serial.available()) {
    uint8_t c = (uint8_t)Serial.read();
    if (rxLen == 0 && c != AURA_SOF) continue;          /* resynchronise on the start byte */
    rxBuf[rxLen++] = c;
    if (rxLen >= 6) {
      uint8_t plen = rxBuf[5];
      size_t need = (plen > AURA_MAX_PAYLOAD) ? 8 : (size_t)(8 + plen);
      if (rxLen >= need) {
        wd_on_bytes(&wd, now, rxBuf, need);            /* oversized frames are rejected here */
        rxLen = 0;
      }
    }
  }
}

/* ---------------------------------------------------------------- LED and buzzer patterns */

static void updateOutputs(uint32_t now, wd_state_t st) {
  bool led = false, buzz = false;
  uint32_t p = 0;
  switch (st) {
    case WD_BOOT:       led = true; break;
    case WD_HEALTHY:    led = (now % 1000) < 120; break;                 /* short heartbeat blink */
    case WD_ALERT:      led = (now % 200) < 100; buzz = led; break;      /* fast blink + buzzer */
    case WD_COMM_FAULT:                                                  /* triple flash, buzzer */
      p = now % 1000;
      led = (p < 100) || (p >= 200 && p < 300) || (p >= 400 && p < 500);
      buzz = p < 100;
      break;
    case WD_RECOVERY:   led = (now % 600) < 300; break;
    default: break;
  }
  digitalWrite(LED_PIN, led ? HIGH : LOW);
  digitalWrite(BUZZER_PIN, buzz ? HIGH : LOW);
}

/* ---------------------------------------------------------------- setup and loop */

void setup() {
  Serial.begin(SENSOR_BAUD);
  pinMode(LED_PIN, OUTPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  wd_init(&wd);
  rxQueue = xQueueCreate(256, sizeof(Rec));

  WiFi.mode(WIFI_STA);                         /* radio on; we never connect to a network */
  esp_wifi_set_promiscuous(false);
  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&snifferCb);
  esp_wifi_set_channel(CHANNELS[0], WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous(true);
  Serial.println("# AURA-Q sensor started");
}

void loop() {
  static uint32_t lastHop = 0, lastStatus = 0;
  static uint8_t hopIdx = 0;
  uint32_t now = millis();

  if (now - lastHop >= HOP_MS) {
    lastHop = now;
    hopIdx = (uint8_t)((hopIdx + 1) % 3);
    esp_wifi_set_channel(CHANNELS[hopIdx], WIFI_SECOND_CHAN_NONE);
  }

  Rec r;
  int sent = 0;
  while (sent < 40 && xQueueReceive(rxQueue, &r, 0) == pdTRUE) {   /* limited so the loop stays responsive */
    printRec(r);
    sent++;
  }

  handleRx(now);
  wd_state_t st = wd_tick(&wd, now);
  updateOutputs(now, st);

  if (now - lastStatus >= 2000) {
    lastStatus = now;
    Serial.printf("S|%lu|%s|%lu|%lu\n", (unsigned long)now, WD_NAMES[st],
                  (unsigned long)dropCount, (unsigned long)wd.rejects);
  }
  delay(1);
}
