#!/usr/bin/env python3
"""Real PQ public keys and signatures (liboqs 0.16.0) for the gas harness. Calldata cost depends
on the byte values, so the harness uses genuine encodings rather than random bytes."""
import json, os, secrets, oqs
out = {}
for alg, name in [("ML-DSA-44", "ML-DSA-44"), ("ML-DSA-65", "ML-DSA-65"), ("ML-DSA-87", "ML-DSA-87"),
                  ("Falcon-512", "Falcon-512"), ("SLH_DSA_PURE_SHA2_128S", "SLH-DSA-128s"),
                  ("SLH_DSA_PURE_SHA2_128F", "SLH-DSA-128f")]:
    with oqs.Signature(alg) as s:
        pk = s.generate_keypair()
        sigs = [s.sign(secrets.token_bytes(32)).hex() for _ in range(8 if "SLH" in alg else 40)]
    out[name] = {"pk": pk.hex(), "sigs": sigs}
    print(name, len(pk), [len(x) // 2 for x in sigs[:3]])
json.dump(out, open("pq_samples.json", "w"))
