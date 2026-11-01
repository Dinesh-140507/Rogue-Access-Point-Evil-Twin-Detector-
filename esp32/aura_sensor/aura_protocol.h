/*
 * AURA-Q protocol and watchdog, written as plain C with no Arduino code.
 *
 * It is the ESP32 version of ipc.py (frame format and CRC) and watchdog.py (state machine).
 * Keeping it separate means the same logic can be compiled and tested on a PC
 * (see esp32/host_tests/test_protocol.c) and used unchanged by the sketch.
 *
 * Frame:  [SOF 0xAA | VER 1B | TYPE 1B | SEQ 2B big-endian | LEN 1B | PAYLOAD 0-32B | CRC16 2B big-endian]
 *         CRC16-CCITT (init 0xFFFF, poly 0x1021) covers VER..PAYLOAD.
 */
#ifndef AURA_PROTOCOL_H
#define AURA_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define AURA_SOF 0xAA
#define AURA_VER 1
#define AURA_T_HEARTBEAT 0x01
#define AURA_T_STATUS 0x02
#define AURA_T_ALERT 0x03
#define AURA_MAX_PAYLOAD 32

#define AURA_HB_TIMEOUT_MS 3000u     /* no valid heartbeat for 3 s -> fault        */
#define AURA_BAD_THRESH 3            /* this many bad frames ...                   */
#define AURA_BAD_WINDOW_MS 3000u     /* ... within 3 s -> fault                    */
#define AURA_RECOVERY_CYCLES 5       /* valid frames needed to leave RECOVERY      */
#define AURA_ALERT_HOLD_MS 5000u     /* stay in ALERT this long after an alert     */

typedef enum { WD_BOOT = 0, WD_HEALTHY, WD_ALERT, WD_COMM_FAULT, WD_RECOVERY } wd_state_t;
static const char* const WD_NAMES[] = {"BOOT", "HEALTHY", "ALERT", "COMM_FAULT", "RECOVERY"};

/* Result codes, in the same order as ipc.parse_frame() checks them. */
typedef enum {
  FR_OK = 0, FR_TOO_SHORT, FR_BAD_SOF, FR_BAD_VER, FR_OVERSIZED, FR_BAD_LENGTH,
  FR_UNKNOWN_TYPE, FR_BAD_CRC, FR_BAD_SEQ
} aura_result_t;

typedef struct {
  uint8_t type;
  uint16_t seq;
  uint8_t plen;
  const uint8_t* payload;
} aura_frame_t;

static inline uint16_t aura_crc16(const uint8_t* d, size_t n) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < n; i++) {
    crc ^= (uint16_t)((uint16_t)d[i] << 8);
    for (int b = 0; b < 8; b++) {
      crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
    }
  }
  return crc;
}

/* Build a frame into out[]; returns the number of bytes written (8 + payload length). */
static inline size_t aura_build(uint8_t type, uint16_t seq, const uint8_t* payload, uint8_t plen, uint8_t* out) {
  out[0] = AURA_SOF;
  out[1] = AURA_VER;
  out[2] = type;
  out[3] = (uint8_t)(seq >> 8);
  out[4] = (uint8_t)(seq & 0xFF);
  out[5] = plen;
  if (plen) memcpy(out + 6, payload, plen);
  uint16_t crc = aura_crc16(out + 1, (size_t)(5 + plen));
  out[6 + plen] = (uint8_t)(crc >> 8);
  out[7 + plen] = (uint8_t)(crc & 0xFF);
  return (size_t)(8 + plen);
}

/* Parse and validate one complete frame. Checks happen in the same order as ipc.parse_frame(). */
static inline aura_result_t aura_parse(const uint8_t* raw, size_t n, aura_frame_t* out) {
  if (n < 8) return FR_TOO_SHORT;
  if (raw[0] != AURA_SOF) return FR_BAD_SOF;
  if (raw[1] != AURA_VER) return FR_BAD_VER;
  uint8_t plen = raw[5];
  if (plen > AURA_MAX_PAYLOAD) return FR_OVERSIZED;
  if (n != (size_t)(8 + plen)) return FR_BAD_LENGTH;
  uint8_t type = raw[2];
  if (type != AURA_T_HEARTBEAT && type != AURA_T_STATUS && type != AURA_T_ALERT) return FR_UNKNOWN_TYPE;
  uint16_t rx_crc = (uint16_t)((raw[n - 2] << 8) | raw[n - 1]);
  if (aura_crc16(raw + 1, n - 3) != rx_crc) return FR_BAD_CRC;
  out->type = type;
  out->seq = (uint16_t)((raw[3] << 8) | raw[4]);
  out->plen = plen;
  out->payload = raw + 6;
  return FR_OK;
}

/* ---------------------------------------------------------------- watchdog state machine */

typedef struct {
  wd_state_t state;
  uint32_t last_valid;  int have_valid;
  uint16_t last_seq;    int have_seq;
  uint32_t bad_t[8];    uint8_t nbad;
  uint32_t rejects;
  uint8_t streak;
  uint32_t alert_until;
} aura_wd_t;

static inline void wd_init(aura_wd_t* w) { memset(w, 0, sizeof *w); w->state = WD_BOOT; }

/* Sequence numbers wrap at 65535; 'a is newer than b' uses modular arithmetic. */
static inline int aura_seq_newer(uint16_t a, uint16_t b) {
  uint16_t d = (uint16_t)(a - b);
  return d >= 1 && d <= 0x7FFF;
}

static inline void wd_note_bad(aura_wd_t* w, uint32_t now) {
  w->rejects++;
  if (w->nbad < 8) {
    w->bad_t[w->nbad++] = now;
  } else {
    memmove(w->bad_t, w->bad_t + 1, 7 * sizeof(uint32_t));
    w->bad_t[7] = now;
  }
}

/* Feed the bytes of one complete frame. Returns the parse/validation result. */
static inline aura_result_t wd_on_bytes(aura_wd_t* w, uint32_t now, const uint8_t* raw, size_t n) {
  aura_frame_t f;
  aura_result_t r = aura_parse(raw, n, &f);
  if (r == FR_OK && w->have_seq && !aura_seq_newer(f.seq, w->last_seq)) r = FR_BAD_SEQ;
  if (r != FR_OK) {
    wd_note_bad(w, now);
    return r;
  }
  w->last_seq = f.seq; w->have_seq = 1;
  w->last_valid = now; w->have_valid = 1;
  if (w->streak < 255) w->streak++;
  if (f.type == AURA_T_ALERT) w->alert_until = now + AURA_ALERT_HOLD_MS;
  return FR_OK;
}

/* Called every loop. Returns the new state. */
static inline wd_state_t wd_tick(aura_wd_t* w, uint32_t now) {
  uint32_t ref = w->have_valid ? w->last_valid : 0;
  uint8_t recent = 0;
  for (uint8_t i = 0; i < w->nbad; i++)
    if (now - w->bad_t[i] <= AURA_BAD_WINDOW_MS) recent++;
  int faulty = (now - ref) > AURA_HB_TIMEOUT_MS || recent >= AURA_BAD_THRESH;
  if (faulty) {
    w->state = WD_COMM_FAULT;
    w->streak = 0;
  } else {
    switch (w->state) {
      case WD_BOOT:       if (w->have_valid) w->state = WD_HEALTHY; break;
      case WD_COMM_FAULT: w->state = WD_RECOVERY; break;
      case WD_RECOVERY:   if (w->streak >= AURA_RECOVERY_CYCLES) w->state = WD_HEALTHY; break;
      case WD_HEALTHY:    if (now < w->alert_until) w->state = WD_ALERT; break;
      case WD_ALERT:      if (now >= w->alert_until) w->state = WD_HEALTHY; break;
      default: break;
    }
  }
  return w->state;
}

#endif /* AURA_PROTOCOL_H */
