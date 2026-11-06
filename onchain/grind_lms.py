#!/usr/bin/env python3
"""Minimal RFC 8554 LMS signer (LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W4) that grinds the
randomizer C so that verification needs a chosen number of Winternitz chain steps.
Used only to validate the linear gas model beyond the honest range. Output: JSON lines."""
import hashlib, os, sys, json, struct
H = lambda b: hashlib.sha256(b).digest()
u32, u16, u8 = (lambda x: struct.pack('>I', x)), (lambda x: struct.pack('>H', x)), (lambda x: struct.pack('>B', x))
n, w, p, ls, h = 32, 4, 67, 4, 5
LMS_T, OTS_T = 5, 3
I, SEED = os.urandom(16), os.urandom(32)
def coef(S, i): return (S[i // 2] >> (4 if i % 2 == 0 else 0)) & 15
def cksm(Q): return u16((sum(15 - coef(Q, i) for i in range(64))) << ls)
def x(q, i): return H(I + u32(q) + u16(i) + b'\xff' + SEED)
def ots_pub(q):
    z = []
    for i in range(p):
        t = x(q, i)
        for j in range(15): t = H(I + u32(q) + u16(i) + u8(j) + t)
        z.append(t)
    return H(I + u32(q) + u16(0x8080) + b''.join(z))
leaves = [H(I + u32(2**h + q) + u16(0x8282) + ots_pub(q)) for q in range(2**h)]
tree = {2**h + q: leaves[q] for q in range(2**h)}
for r in range(2**h - 1, 0, -1): tree[r] = H(I + u32(r) + u16(0x8383) + tree[2 * r] + tree[2 * r + 1])
pk = u32(LMS_T) + u32(OTS_T) + I + tree[1]
def steps_of(Q):
    QC = Q + cksm(Q)
    return sum(15 - coef(QC, i) for i in range(p))
def sign(q, msg, target):
    best = None
    for _ in range(20_000_000):
        C = os.urandom(32)
        Q = H(I + u32(q) + u16(0x8181) + C + msg)
        s = steps_of(Q)
        if s >= target: best = (C, Q, s); break
    C, Q, s = best
    QC = Q + cksm(Q); y = []
    for i in range(p):
        t = x(q, i)
        for j in range(coef(QC, i)): t = H(I + u32(q) + u16(i) + u8(j) + t)
        y.append(t)
    path, node = [], 2**h + q
    while node > 1: path.append(tree[node ^ 1]); node >>= 1
    sig = u32(q) + u32(OTS_T) + C + b''.join(y) + u32(LMS_T) + b''.join(path)
    return sig, s
targets = [int(t) for t in sys.argv[1:]] or [500, 560, 600, 630, 650, 670, 690]
print(json.dumps({"pk": pk.hex()}), flush=True)
for q, t in enumerate(targets):
    msg = os.urandom(32); sig, s = sign(q, msg, t)
    print(json.dumps({"msg": msg.hex(), "sig": sig.hex(), "steps": s}), flush=True)
