# pq-iot-auth

Code and data for the article **"Post-Quantum Authentication of IoT Data on Ethereum: Signatures, the Calldata Floor, and the Case for Device-Signed Merkle Roots"** (M.-F. Sie, 2026, manuscript submitted).

The study measures what post-quantum (PQ) authentication of IoT records costs on Ethereum under the current execution rules (Osaka: EIP-7623 calldata floor, EIP-7825 per-transaction gas cap), for ML-DSA, Falcon and SLH-DSA, with today's Solidity verifiers and with proposed precompiles (EIP-8355, EIP-8052).

## Key results

| Design | Gas per record | Records per transaction |
|---|---:|---:|
| ECDSA, one signature per record (batched) | 9,211 | 1,816 |
| ML-DSA-44, one signature per record, Solidity verifier | 0.9M - 8.2M | 2 - 18 |
| ML-DSA-44, one signature per record, precompile (EIP-8355) | 107,090 | 159 |
| ML-DSA-44, device-signed Merkle root over 100 records, precompile | 2,813 | 6,000 |
| ML-DSA-44, device-signed Merkle root over 1,000 records, Solidity verifier | 2,447 | - |

With device-signed Merkle roots, PQ authentication is cheaper than per-record ECDSA **with today's Solidity verifiers**, i.e. without any protocol change.

## Repository layout

```
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
node pq_gasbench.mjs --out results                          # ~10 min; --quick for a smoke test
./reproduce_solidity_verifiers.sh                           # needs Foundry + solc 0.8.25/0.8.30
```

Figures:
```sh
cd figures && python3 make_figures.py --onchain ../onchain/results --offchain ../offchain/results --out out
pdflatex fig1_designs.tex
```

Gas results are deterministic. The harness checks the EIP-7623 pricing formula against the EVM on every PQ transaction (189/189 exact in the published run). Device timings depend on the hardware.

## Notes

- PQ verification in the harness is priced by substitution: the contract calls an empty account with the full EIP-8355 input, so calldata, memory, hashing, registry and anchoring costs are measured; the verification gas of each implementation (reproduced Solidity verifiers or proposed precompile prices) is then added. ECDSA is verified for real with `ecrecover`.
- The ZKNOX Solidity verifiers are third-party, experimental and unaudited; they are not included in this repository and are fetched by `reproduce_solidity_verifiers.sh` at pinned commits.
- `PQAnchor.sol` is research code, not audited. Production use should add domain separation between Merkle leaves and internal nodes.

## License

MIT (see `LICENSE`). Cite via `CITATION.cff`.
