#!/usr/bin/env python3
"""Line-based LMS signing service for the gas harness (RFC 8554 via hsslms).
stdin : {"ots": "W4", "msg": "<32-byte hex>"}  or  {"ots": "W4", "pk": true}
stdout: {"sig": "<hex>"} / {"pk": "<hex>"}
One LMS_SHA256_M32_H10 key per LM-OTS parameter set; leaves are consumed in order (stateful)."""
import json, sys, time
from hsslms import LMS_Priv, LMS_ALGORITHM_TYPE as L, LMOTS_ALGORITHM_TYPE as O
OTS = {"W2": O.LMOTS_SHA256_N32_W2, "W4": O.LMOTS_SHA256_N32_W4, "W8": O.LMOTS_SHA256_N32_W8}
keys = {}
def key(w):
    if w not in keys:
        t = time.time(); keys[w] = LMS_Priv(L.LMS_SHA256_M32_H10, OTS[w], num_cores=4)
        print(f"keygen {w} {time.time()-t:.1f}s", file=sys.stderr, flush=True)
    return keys[w]
for line in sys.stdin:
    r = json.loads(line)
    k = key(r["ots"])
    if r.get("pk"):
        out = {"pk": k.gen_pub().get_pubkey().hex()}
    else:
        out = {"sig": k.sign(bytes.fromhex(r["msg"])).hex()}
    print(json.dumps(out), flush=True)
