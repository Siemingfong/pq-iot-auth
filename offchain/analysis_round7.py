#!/usr/bin/env python3
"""Analytical results added in the seventh revision: commit-now-verify-later costs, LoRaWAN airtime as a
function of record size with burst and frame-loss constraints, gas per record as a function of the calldata
floor price (packed), and an estimate for an on-chain SLH-DSA-SHA2-128s verifier. Inputs are measured
values from onchain/results7 and results8."""
import math
# commit now, verify later (DR-0, k = 100)
ECDSA_DR0, HYBRID_DR0C, LMS_H15 = 254, 1057, 3379
print("commit once per device:", 22100 + 32 * 16, "gas; hybrid premium per device-root:", (HYBRID_DR0C - ECDSA_DR0) * 100)
# LoRaWAN EU868 (Semtech AN1200.13), 125 kHz, CR 4/5, 8-symbol preamble, CRC, 13-byte MAC overhead
def airtime(pl, sf, bw=125e3):
    PL = pl + 13; de = 1 if sf >= 11 else 0; ts = 2 ** sf / bw
    return (12.25 + 8 + max(math.ceil((8 * PL - 4 * sf + 44) / (4 * (sf - 2 * de))) * 5, 0)) * ts
MX = {7: 222, 10: 51}
def send(nb, sf):
    f, r = divmod(nb, MX[sf]); return f * airtime(MX[sf], sf) + (airtime(r, sf) if r else 0), f + (1 if r else 0)
for rec in (16, 32, 64, 116):
    pr, _ = send(rec + 2420, 10); r, _ = send(rec, 10); sg, _ = send(2428, 10)
    print(f"record {rec} B, SF10: PR ML-DSA-44 {6*pr:.1f} s/h, DR (k=144) {6*(r+sg/144):.1f} s/h")
for p in (0.01, 0.05, 0.10):
    print(f"frame loss {p:.0%}: P(50 frames intact) {(1-p)**50:.2f}, frames with selective retransmission {50/(1-p):.1f}")
# floor price sweep (packed): per record = max(measured execution-bound cost, 21000/n + f * bytes per record)
for lab, now, bpr, n in [("ECDSA DR-0", 238, 1.4, 1000), ("ML-DSA-44 DR-0C", 998, 24.7, 1000), ("ML-DSA-87 DR-0C", 1878, 46.8, 1000),
                         ("LMS-H10 DR-0", 3343, 26.2, 1000), ("ECDSA PR", 12428, 166.3, 50), ("ML-DSA-44 PR", 110529, 2779.7, 50)]:
    print(lab, [round(max(now, 21000 / n + f * bpr)) if f > 40 else now for f in (40, 64, 96, 128)])
# SLH-DSA-SHA2-128s verifier estimate (lower bound)
calls = 1 + (14 * 13 + 1) + 7 * (35 * 7.5 + 1 + 9)
verify = calls * (315 + 24) + 115000 + 7 * (60 + 12 * 19 + 100)
T = 7856 * 4 + 500; dev = 2100 + max(4 * T + 21000 + verify, 10 * T)
print(f"SLH-DSA-128s: {calls:.0f} hash calls, ~{verify/1e6:.2f}M gas, DR-0 ~{dev/100:.0f} gas per record (k=100)")
