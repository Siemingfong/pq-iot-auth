#!/usr/bin/env python3
"""Exact distribution of Winternitz chain steps in LMOTS verification (w = 4, n = 32) for honest
signers, with quantiles and the theoretical maximum (Appendix A of the paper)."""
import numpy as np
p = np.zeros(961); p[0] = 1.0
for _ in range(64): p = np.convolve(p, np.ones(16) / 16)[:961]
def steps(S):
    ck = (S << 4) & 0xffff
    return S + sum(15 - ((ck >> s) & 15) for s in (12, 8, 4))
dist = {}
for S in range(961): dist[steps(S)] = dist.get(steps(S), 0) + p[S]
ks = np.array(sorted(dist)); ps = np.array([dist[k] for k in ks]); cdf = np.cumsum(ps)
mean = (ks * ps).sum(); sd = ((ks - mean) ** 2 * ps).sum() ** 0.5
print(f"mean {mean:.1f}  sd {sd:.1f}  max {ks.max()}")
for q in (1e-3, 1e-6, 1e-9, 1e-12):
    print(f"quantile 1-{q:g}: {ks[np.searchsorted(cdf, 1 - q)]} steps")
