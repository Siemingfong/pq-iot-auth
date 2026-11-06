# pq-iot-auth

[![arXiv](https://img.shields.io/badge/arXiv-2611.08108-b31b1b.svg)](https://arxiv.org/abs/2611.08108) [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23998670.svg)](https://doi.org/10.5281/zenodo.23998670)

Archived releases: v2.6 [10.5281/zenodo.23998670](https://doi.org/10.5281/zenodo.23998670) (journal submission); v2.5 [10.5281/zenodo.23996908](https://doi.org/10.5281/zenodo.23996908); v2.4 [10.5281/zenodo.23995262](https://doi.org/10.5281/zenodo.23995262); v2.3 [10.5281/zenodo.23970176](https://doi.org/10.5281/zenodo.23970176) (arXiv v1); v2.2 [10.5281/zenodo.23969084](https://doi.org/10.5281/zenodo.23969084).

Code and data for the article ([arXiv:2611.08108](https://arxiv.org/abs/2611.08108)) **"Post-Quantum Authentication of IoT Data on Ethereum: Signatures, the Calldata Floor, and the Case for Device-Signed Merkle Roots"** (M.-F. Sie, 2026, manuscript submitted).

The study measures what post-quantum (PQ) authentication of IoT records costs on Ethereum under the current execution rules (Osaka: EIP-7623 calldata floor, EIP-7825 per-transaction gas cap), for ML-DSA, Falcon and SLH-DSA, with today's Solidity verifiers and with proposed precompiles (EIP-8355, EIP-8052).

## Key results

Gas per record (revised version; device-signed roots compared with ECDSA in the same design):

| Design | ECDSA | ML-DSA-44, precompile | LMS-H10-W4, Solidity (today) |
|---|---:|---:|---:|
| One signature per record, batches of 50 | 13,413 | 112,508 | 322,358 |
| Device-signed roots, leaves posted, k = 1,000 | 1,290 | 1,435 | 1,389 |
| Device-signed roots, leaves posted, k = 100 | 1,385 | 2,832 | 4,212 |
| Device-signed roots, root only, k = 100 | 254 | 1,031 (key on-chain) | 3,359 |

Post-quantum device authentication is deployable today (LMS verified in Solidity) at a premium that device-side batching keeps to a few thousand gas per record.

## Repository layout

```
onchain/ (revision)
  PQAnchor2.sol                 device-signed roots with replay-protected messages (chain id, contract,
                                device, epoch, root, count), leaf-free and leaf-posting variants,
                                keys in calldata or on-chain (SSTORE2), PQ-authorized registration
  LMSVerifier.sol               RFC 8554 LMS verifier in Solidity (SHA-256 precompile) + gas Meter
  lms_signer.py                 LMS signing service (hsslms) used by the harness
  pq_gasbench2.mjs              revision experiments (DR-L / DR-0 / DR-0C, registration, max devices)
  validate_exact.mjs            empirical check of the verification-cost substitution
  dr_k1000.mjs                  DR-L at k = 1,000 with 4 devices per transaction
  results2/                     revision results (CSV/JSON)
  PQAnchor5.sol, pq_gasbench7.mjs, pq_gasbench8.mjs, results7/, results8/
                                current (unreleased): in-place Merkle, real P-256, long-lived LMS/HSS,
                                registration/revocation, floor-aware model points
  PQAnchor4.sol, pq_gasbench5.mjs, pq_gasbench6.mjs, enc_fix.mjs, grind_lms.py,
  lms_step_distribution.py, results5/, results6/
                                v2.4: final contract (reordering-tolerant epochs, packed calldata),
                                main tables re-measured, LMS step distribution and grinding
  LMSVerifier3.sol, pq_gasbench4.mjs, test_lms3.mjs, results4/
                                v2.3: LMS n = 24, P-256 and hybrid rows, relaxed-epoch re-run
  PQAnchor3.sol, LMSVerifier2.sol, pq_gasbench3.mjs, pr_warm.mjs, results3/
                                v2.2: replay-protected per-record signatures, LMS-H15 and HSS,
                                worst-case LMS verification
offchain/
  pq_device_bench.py            device-side sign/verify time and sizes (liboqs), root-signing cost
  results/                      measured CSV/JSON
onchain/
  PQAnchor.sol                  anchoring contract: per-record (PR) and device-signed roots (DR)
  pq_gasbench.mjs               transaction harness on an Osaka-rule EVM (EthereumJS)
  make_samples.py               genuine PQ keys/signatures (liboqs) for realistic calldata
  pq_samples.json               samples used in the paper
  reproduce_solidity_verifiers.sh   Foundry reproduction of the ZKNOX verifier gas (Table 1)
  results/                      measured CSV/JSON
figures/
  make_figures.py               Figures 2-4 from the CSV results
  fig1_designs.tex              Figure 1 (TikZ)
  out/                          generated figures (PDF/PNG)
scripts/
  install_liboqs.sh             builds liboqs 0.16.0 + liboqs-python (also for Raspberry Pi OS)
```

## Reproduce

Device side (Python 3.10+):
```sh
./scripts/install_liboqs.sh
cd offchain && python3 pq_device_bench.py --out results      # ~2 min
```

On-chain (Node.js 20+):
```sh
cd onchain
npm install
node pq_gasbench.mjs --out results                          # first version (per-record design), ~10 min
node pq_gasbench2.mjs --out results2                        # revision experiments, ~15 min
node validate_exact.mjs --out results2 && node dr_k1000.mjs --out results2
./reproduce_solidity_verifiers.sh                           # needs Foundry + solc 0.8.25/0.8.30
```

Figures:
```sh
cd figures && python3 make_figures.py --onchain ../onchain/results --onchain2 ../onchain/results2 --offchain ../offchain/results --out out
pdflatex fig1_designs.tex
```

Gas results are deterministic. The harness checks the EIP-7623 pricing formula against the EVM on every PQ transaction (189/189 exact in the published run). Device timings depend on the hardware.

## Device benchmark on ARM64 without hardware

`.github/workflows/device-bench.yml` runs `offchain/pq_device_bench.py` on GitHub-hosted runners
(ARM64 Cobalt 100 / Neoverse N2, and x86-64), free for public repositories: Actions tab ->
`device-bench` -> Run workflow, then download the artifacts. These are server-class ARM cores,
not IoT devices; Cortex-M4 figures are taken from pqm4.

## Notes

- PQ verification in the harness is priced by substitution: the contract calls an empty account with the full EIP-8355 input, so calldata, memory, hashing, registry and anchoring costs are measured; the verification gas of each implementation (reproduced Solidity verifiers or proposed precompile prices) is then added. ECDSA is verified for real with `ecrecover`.
- The ZKNOX Solidity verifiers are third-party, experimental and unaudited; they are not included in this repository and are fetched by `reproduce_solidity_verifiers.sh` at pinned commits.
- `PQAnchor.sol`, `PQAnchor2.sol` and `LMSVerifier.sol` are research code, not audited. `PQAnchor2.sol` uses domain-separated Merkle nodes (leaf = keccak(0x00 || record), node = keccak(0x01 || left || right)).
- LMS is stateful: a device must persist its one-time-key counter before releasing each signature.

## License

MIT (see `LICENSE`). Cite via `CITATION.cff`.
