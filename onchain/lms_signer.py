#!/usr/bin/env python3
"""Line-based LMS/HSS signing service (RFC 8554 via hsslms). Requests:
{"key": "H10-W4" | "H10-W2" | "H10-W8" | "H15-W4" | "HSS-H10W4x2", "pk": true}  -> {"pk": hex}
{"key": ..., "msg": "<hex>"}                                                       -> {"sig": hex}"""
import json, sys, time
from hsslms import LMS_Priv, HSS_Priv, LMS_ALGORITHM_TYPE as L, LMOTS_ALGORITHM_TYPE as O
H = {"H10": L.LMS_SHA256_M32_H10, "H15": L.LMS_SHA256_M32_H15, "M24H10": L.LMS_SHA256_M24_H10}
W = {"W2": O.LMOTS_SHA256_N32_W2, "W4": O.LMOTS_SHA256_N32_W4, "W8": O.LMOTS_SHA256_N32_W8,
     "N24W4": O.LMOTS_SHA256_N24_W4, "N24W8": O.LMOTS_SHA256_N24_W8, "N24W2": O.LMOTS_SHA256_N24_W2}
keys = {}
def key(name):
    if name not in keys:
        t = time.time()
        if name == "HSS-M24-H10W4x2":
            keys[name] = HSS_Priv([H["M24H10"], H["M24H10"]], W["N24W4"], num_cores=4)
        elif name.startswith("HSS"):
            keys[name] = HSS_Priv([H["H10"], H["H10"]], W["W4"], num_cores=4)
        else:
            if name.startswith("M24"):
                _, h, w = name.split("-"); keys[name] = LMS_Priv(H["M24" + h], W["N24" + w], num_cores=4)
            else:
                h, w = name.split("-"); keys[name] = LMS_Priv(H[h], W[w], num_cores=4)
        print(f"keygen {name} {time.time()-t:.1f}s", file=sys.stderr, flush=True)
    return keys[name]
for line in sys.stdin:
    r = json.loads(line); k = key(r.get("key") or ("H10-" + r["ots"]))
    out = {"pk": k.gen_pub().get_pubkey().hex()} if r.get("pk") else {"sig": k.sign(bytes.fromhex(r["msg"])).hex()}
    print(json.dumps(out), flush=True)
