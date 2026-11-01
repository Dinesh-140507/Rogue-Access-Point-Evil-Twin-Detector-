/*
 * Host-side test for aura_protocol.h (no ESP32 needed).
 *   gcc -std=c99 -Wall -Wextra -I../aura_sensor test_protocol.c -o test_protocol && ./test_protocol
 * Prints PASS/FAIL lines and exits non-zero on any failure.
 * It also prints a golden frame so the Python side can be cross-checked (see README).
 */
#include <stdio.h>
#include <stdlib.h>
#include "aura_protocol.h"

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("PASS  %s\n", msg); else { printf("FAIL  %s\n", msg); failures++; } } while (0)

int main(void) {
  /* 1. CRC check value for CRC-16/CCITT-FALSE: "123456789" -> 0x29B1 */
  CHECK(aura_crc16((const uint8_t*)"123456789", 9) == 0x29B1, "CRC16 check value 0x29B1");

  /* 2. Build and parse a frame */
  uint8_t buf[64];
  const uint8_t pl[] = {'h', 'i'};
  size_t n = aura_build(AURA_T_STATUS, 3, pl, 2, buf);
  aura_frame_t f;
  CHECK(aura_parse(buf, n, &f) == FR_OK && f.type == AURA_T_STATUS && f.seq == 3 && f.plen == 2,
        "round trip parses");

  /* 3. Corrupt one byte -> CRC error */
  buf[6] ^= 0x01;
  CHECK(aura_parse(buf, n, &f) == FR_BAD_CRC, "single bit flip rejected as bad CRC");
  buf[6] ^= 0x01;

  /* 4. Structural rejections */
  uint8_t bad[64];
  memcpy(bad, buf, n); bad[0] = 0x00;
  CHECK(aura_parse(bad, n, &f) == FR_BAD_SOF, "bad SOF rejected");
  memcpy(bad, buf, n); bad[1] = 2;
  CHECK(aura_parse(bad, n, &f) == FR_BAD_VER, "bad version rejected");
  memcpy(bad, buf, n); bad[5] = 99;
  CHECK(aura_parse(bad, n, &f) == FR_OVERSIZED, "oversized payload rejected");
  memcpy(bad, buf, n); bad[5] = 3;
  CHECK(aura_parse(bad, n, &f) == FR_BAD_LENGTH, "length mismatch rejected");
  n = aura_build(0x7F, 9, NULL, 0, buf);
  CHECK(aura_parse(buf, n, &f) == FR_UNKNOWN_TYPE, "unknown message type rejected (valid CRC)");

  /* 5. Random 1-3 bit flips in a valid frame: all must be rejected */
  srand(7);
  n = aura_build(AURA_T_HEARTBEAT, 100, NULL, 0, buf);
  int rejected = 0, tested = 0;
  for (int trial = 0; trial < 2000; trial++) {
    uint8_t c[64];
    memcpy(c, buf, n);
    int flips = 1 + rand() % 3;
    for (int k = 0; k < flips; k++) c[rand() % n] ^= (uint8_t)(1u << (rand() % 8));
    if (memcmp(c, buf, n) == 0) continue;
    tested++;
    if (aura_parse(c, n, &f) != FR_OK) rejected++;
  }
  printf("      bit-flip test: %d/%d rejected\n", rejected, tested);
  CHECK(rejected == tested, "all 1-3 bit-flip corruptions rejected");

  /* 6. Watchdog timeline: heartbeats each second until t=10 s, silence until t=20 s, then resume */
  aura_wd_t wd; wd_init(&wd);
  uint32_t seq = 0, t_fault = 0, t_healthy_again = 0;
  int saw_healthy = 0, saw_fault = 0;
  for (uint32_t ms = 0; ms <= 32000; ms++) {
    if (ms % 1000 == 0 && (ms <= 10000 || ms >= 20000)) {
      seq++;
      n = aura_build(AURA_T_HEARTBEAT, (uint16_t)seq, NULL, 0, buf);
      wd_on_bytes(&wd, ms, buf, n);
    }
    wd_state_t s = wd_tick(&wd, ms);
    if (s == WD_HEALTHY && ms < 10000) saw_healthy = 1;
    if (s == WD_COMM_FAULT && !saw_fault) { saw_fault = 1; t_fault = ms; }
    if (s == WD_HEALTHY && ms > 20000 && !t_healthy_again) t_healthy_again = ms;
  }
  printf("      heartbeats stop at 10.0 s -> COMM_FAULT at %.3f s; back to HEALTHY at %.3f s\n",
         t_fault / 1000.0, t_healthy_again / 1000.0);
  CHECK(saw_healthy, "reaches HEALTHY while heartbeats arrive");
  CHECK(saw_fault && t_fault > 13000 && t_fault <= 13100, "fault declared 3 s after the last heartbeat");
  CHECK(t_healthy_again > 20000 && t_healthy_again <= 26000, "recovers after 5 valid frames (RECOVERY state)");

  /* 7. An alert frame moves HEALTHY -> ALERT and holds for 5 s */
  aura_wd_t w2; wd_init(&w2);
  seq = 0;
  for (uint32_t ms = 0; ms <= 4000; ms += 1000) {
    seq++; n = aura_build(AURA_T_HEARTBEAT, (uint16_t)seq, NULL, 0, buf);
    wd_on_bytes(&w2, ms, buf, n);
  }
  wd_tick(&w2, 4000);                       /* BOOT -> HEALTHY on the first tick */
  seq++;
  uint8_t pay[4] = {90, 3, 0, 0};
  n = aura_build(AURA_T_ALERT, (uint16_t)seq, pay, 4, buf);
  wd_on_bytes(&w2, 4500, buf, n);
  wd_state_t s_alert = wd_tick(&w2, 4600);
  seq++; n = aura_build(AURA_T_HEARTBEAT, (uint16_t)seq, NULL, 0, buf);
  wd_on_bytes(&w2, 5000, buf, n);
  wd_state_t s_hold = wd_tick(&w2, 5100);
  CHECK(s_alert == WD_ALERT, "alert frame switches the board to ALERT");
  CHECK(s_hold == WD_ALERT, "ALERT is held while the hold time runs");

  /* 8. An out-of-order sequence number is rejected */
  aura_wd_t w3; wd_init(&w3);
  n = aura_build(AURA_T_HEARTBEAT, 10, NULL, 0, buf); wd_on_bytes(&w3, 0, buf, n);
  n = aura_build(AURA_T_HEARTBEAT, 9, NULL, 0, buf);
  CHECK(wd_on_bytes(&w3, 10, buf, n) == FR_BAD_SEQ, "out-of-order sequence number rejected");

  /* 9. Golden frame for the Python cross-check: heartbeat, seq 1, no payload */
  n = aura_build(AURA_T_HEARTBEAT, 1, NULL, 0, buf);
  printf("GOLDEN_HEARTBEAT_SEQ1=");
  for (size_t i = 0; i < n; i++) printf("%02X", buf[i]);
  printf("\n");

  printf("\n%s (%d failure(s))\n", failures ? "SOME TESTS FAILED" : "ALL TESTS PASSED", failures);
  return failures ? 1 : 0;
}
