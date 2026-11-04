#!/usr/bin/env python3
"""
Device- and aggregator-side costs of post-quantum signatures for IoT records.

Schemes: ML-DSA-44/65/87 (FIPS 204), Falcon-512/1024 (FN-DSA, draft FIPS 206),
SLH-DSA-SHA2-128s/128f (FIPS 205) via liboqs; ECDSA secp256k1 (libsecp256k1) and
P-256 (OpenSSL) as classical baselines.

Measures key generation, signing and verification time (median), and public-key and
signature sizes. Also measures the cost of the "sign-the-root" pattern: hashing k records
into a Merkle tree on the device and signing only the root.

Usage: python3 pq_device_bench.py [--quick] [--out results]
"""
import argparse, csv, hashlib, json, os, platform, secrets, statistics, time
import oqs
import coincurve
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

PQ = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Falcon-512", "Falcon-1024",
      "SLH_DSA_PURE_SHA2_128F", "SLH_DSA_PURE_SHA2_128S"]
LABEL = {"SLH_DSA_PURE_SHA2_128F": "SLH-DSA-SHA2-128f", "SLH_DSA_PURE_SHA2_128S": "SLH-DSA-SHA2-128s"}
RECORD = 116   # bytes: camera type 32 | timestamp 8 | checksum 32 | storage pointer 20 | device id 24


def med(fn, reps):
    ts = []
    for _ in range(reps):
        t0 = time.perf_counter(); fn(); ts.append(time.perf_counter() - t0)
    return statistics.median(ts) * 1e3


def merkle_root(leaves):
    level = leaves
    while len(level) > 1:
        level = [hashlib.sha3_256(level[i] + (level[i + 1] if i + 1 < len(level) else b"")).digest()
                 if i + 1 < len(level) else level[i] for i in range(0, len(level), 2)]
    return level[0]


def bench(reps):
    rows = []
    msg = secrets.token_bytes(RECORD)
    for alg in PQ:
        r = max(5, reps // (50 if "SLH" in alg and alg.endswith("S") else 1))
        with oqs.Signature(alg) as s:
            kg = med(lambda: oqs.Signature(alg).generate_keypair(), max(5, r // 4))
            pk = s.generate_keypair()
            sig = s.sign(msg)
            sign_ms = med(lambda: s.sign(msg), r)
            sigs = [s.sign(msg) for _ in range(20)]
            sig_len = statistics.median(len(x) for x in sigs)        # Falcon signatures vary in length
            with oqs.Signature(alg) as v:
                ver_ms = med(lambda: v.verify(msg, sig, pk), r)
                assert v.verify(msg, sig, pk)
        rows.append({"scheme": LABEL.get(alg, alg), "keygen_ms": round(kg, 4), "sign_ms": round(sign_ms, 4),
                     "verify_ms": round(ver_ms, 4), "pk_bytes": len(pk), "sig_bytes": int(sig_len),
                     "sig_bytes_max": max(len(x) for x in sigs)})
        print(f"  {rows[-1]['scheme']:20s} sign {sign_ms:8.3f} ms  verify {ver_ms:7.3f} ms  pk {len(pk):5d} B  sig {int(sig_len):6d} B", flush=True)
    # classical baselines
    k = coincurve.PrivateKey()
    s = k.sign_recoverable(msg)
    rows.append({"scheme": "ECDSA secp256k1", "keygen_ms": round(med(coincurve.PrivateKey, reps), 4),
                 "sign_ms": round(med(lambda: k.sign_recoverable(msg), reps), 4),
                 "verify_ms": round(med(lambda: coincurve.PublicKey.from_signature_and_message(s, msg), reps), 4),
                 "pk_bytes": 33, "sig_bytes": 65, "sig_bytes_max": 65})
    p = ec.generate_private_key(ec.SECP256R1()); ps = p.sign(msg, ec.ECDSA(hashes.SHA256())); pp = p.public_key()
    rows.append({"scheme": "ECDSA P-256", "keygen_ms": round(med(lambda: ec.generate_private_key(ec.SECP256R1()), reps), 4),
                 "sign_ms": round(med(lambda: p.sign(msg, ec.ECDSA(hashes.SHA256())), reps), 4),
                 "verify_ms": round(med(lambda: pp.verify(ps, msg, ec.ECDSA(hashes.SHA256())), reps), 4),
                 "pk_bytes": 33, "sig_bytes": 64, "sig_bytes_max": 72})
    for r_ in rows[-2:]:
        print(f"  {r_['scheme']:20s} sign {r_['sign_ms']:8.3f} ms  verify {r_['verify_ms']:7.3f} ms", flush=True)
    return rows


def bench_root(reps, ks):
    """Device-side cost of hashing k records into a Merkle tree (SHA3-256) and signing the root."""
    rows = []
    with oqs.Signature("ML-DSA-44") as s44, oqs.Signature("Falcon-512") as f512:
        s44.generate_keypair(); f512.generate_keypair()
        for k in ks:
            recs = [secrets.token_bytes(RECORD) for _ in range(k)]
            t_tree = med(lambda: merkle_root([hashlib.sha3_256(x).digest() for x in recs]), reps)
            rows.append({"records_k": k, "merkle_ms": round(t_tree, 4),
                         "per_record_us_mldsa44": round((t_tree + med(lambda: s44.sign(b"r" * 32), reps)) / k * 1e3, 3),
                         "per_record_us_falcon512": round((t_tree + med(lambda: f512.sign(b"r" * 32), reps)) / k * 1e3, 3)})
            print(f"  k={k:5d} tree {t_tree:8.3f} ms  per-record ML-DSA-44 {rows[-1]['per_record_us_mldsa44']:8.2f} us  Falcon-512 {rows[-1]['per_record_us_falcon512']:8.2f} us")
    return rows


def env():
    cpu = "unknown"
    try:
        cpu = next(l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name"))
    except Exception:
        pass
    from importlib.metadata import version
    return {"cpu": cpu, "python": platform.python_version(), "liboqs": oqs.oqs_version(),
            "liboqs_python": oqs.oqs_python_version(), "coincurve": version("coincurve"),
            "cryptography": version("cryptography"), "record_bytes": RECORD}


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--quick", action="store_true"); ap.add_argument("--out", default="results")
    a = ap.parse_args(); os.makedirs(a.out, exist_ok=True)
    reps = 21 if a.quick else 201
    e = env(); print(json.dumps(e, indent=1))
    rows = bench(reps)
    root = bench_root(max(5, reps // 10), [1, 10, 100, 1000])
    for name, data in (("pq_device.csv", rows), ("pq_root_signing.csv", root)):
        with open(os.path.join(a.out, name), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(data[0])); w.writeheader(); w.writerows(data)
    json.dump(e, open(os.path.join(a.out, "pq_device_env.json"), "w"), indent=2)


if __name__ == "__main__":
    main()
