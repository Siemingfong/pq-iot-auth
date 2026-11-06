#!/usr/bin/env python3
"""LoRaWAN EU868 airtime, duty cycle and transmit energy per record (Semtech AN1200.13 time-on-air).
Assumptions: BW 125 kHz, CR 4/5, 8-symbol preamble, explicit header, CRC on, 13-byte MAC overhead,
max application payload 222 B (SF7) / 51 B (SF10), 40 mA at 3.3 V while transmitting."""
import math
def airtime(pl_app, sf, bw=125e3, cr=1, preamble=8):
    PL = pl_app + 13; de = 1 if sf >= 11 else 0; tsym = (2 ** sf) / bw
    n = 8 + max(math.ceil((8 * PL - 4 * sf + 28 + 16) / (4 * (sf - 2 * de))) * (cr + 4), 0)
    return (preamble + 4.25) * tsym + n * tsym
MAXPL = {7: 222, 10: 51}
def send(nbytes, sf):
    full, rest = divmod(nbytes, MAXPL[sf])
    return full * airtime(MAXPL[sf], sf) + (airtime(rest, sf) if rest else 0)
REC, I_TX, V = 116, 0.040, 3.3
for sf in (7, 10):
    print(f"SF{sf}")
    for lab, sig in [("PR ECDSA", 65), ("PR Falcon-512", 656), ("PR ML-DSA-44", 2420), ("PR LMS-H10-W4", 2508)]:
        t = send(REC + sig, sf); print(f"  {lab:16s} {t*1000:7.0f} ms/record  {6*t:6.1f} s/hour  {t*I_TX*V*1000:7.1f} mJ")
    for lab, sig in [("DR ML-DSA-44", 2428), ("DR LMS-H10-W4", 2516), ("DR HSS H10/H10", 5084)]:
        t = send(REC, sf) + send(sig, sf) / 100; print(f"  {lab:16s} {t*1000:7.0f} ms/record  {6*t:6.1f} s/hour  {t*I_TX*V*1000:7.1f} mJ  (k=100)")
