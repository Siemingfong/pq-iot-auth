# Changelog

## Unreleased (v2.8)
- Repository completed: all contracts, harnesses, results and figure sources (68 files were missing from earlier releases).
- `onchain/results-sepolia/`: measurements on the Sepolia testnet (6 Nov 2026, Geth v1.17.9, 68 transactions). ECDSA and P-256 match the EthereumJS devnet-8 figures exactly, LMS/HSS within signature noise; registration within 12 gas and contract deployment identical.
- `onchain/results-anvil-osaka/`: the same script on a local revm-based node under Osaka rules, reproducing the EthereumJS Osaka figures (independent EVM implementation).
- `regcheck.mjs`, `deploycheck.mjs`: registration and deployment gas under EthereumJS devnet-8 for the comparison with Sepolia.
- `onchain/sepolia_measure.mjs` and `.github/workflows/sepolia.yml`: gas measurement on the Sepolia testnet (ECDSA, P-256, LMS-H10, LMS-H15, HSS) using the same transaction builders as `pq_gasbench10.mjs`; manual GitHub Actions workflow with a dry-run default. Tested end to end on a local anvil node (revm, Osaka rules), where it reproduces the EthereumJS figures.

## v2.7 (journal submission, 2026-11-06)
- `pq_gasbench10.mjs`: draft precompiles (EIP-8355, EIP-8052, EIP-8051) registered as custom EVM precompiles that charge their proposed prices, so every transaction is executed end to end; runs under Osaka or Amsterdam (`--fork`). Under Osaka it reproduces the substituted figures within 0.02%. Results in `onchain/results10-osaka/` and `onchain/results10-amsterdam/` (Glamsterdam devnet-8 schedule as implemented in EthereumJS 10.1.3).
- Fixed: the largest per-record P-256 batch was capped by the bisection's search range (600); the corrected value is 1,010 records.
- `test_rfc9858.mjs`, `rfc9858_vectors.json`: the verifier passes the RFC 9858 Appendix A SHA-256/192 test vectors (n = 24); 600 mutated signatures, none accepted.

## v2.6 (2026-11-06)
- `offchain/analysis_round7.py`: commit-now-verify-later costs, LoRaWAN record-size/burst/loss analysis, floor-price sweep, SLH-DSA estimate.
- `RFCTest.sol`, `test_rfc.mjs`, `rfc8554_vectors.json`: the Solidity LMS/HSS verifier passes the RFC 8554 Appendix F test vectors; differential fuzzing with 1,200 structurally mutated signatures (none accepted).
- `pq_gasbench9.mjs`: per-record signatures with HSS H10/H10 (the configuration that lasts at 144 signatures per day) and LMS-H15 with SHA-256/192. Results in `onchain/results9/`.

## v2.5 (2026-11-06)
- `PQAnchor5.sol`: Merkle hashing in place (no memory growth per hash), leaves copied with calldatacopy in the packed path, P-256 verified for real via the EIP-7951 precompile, no key load in no-verification modes.
- `pq_gasbench7.mjs`: all main tables re-measured on PQAnchor5, with real P-256 and per-record cost at the largest batch; every transaction checked for skipped devices/records. Results in `onchain/results7/`.
- `pq_gasbench8.mjs`: long-lived LMS configurations (H15, HSS H10/H10 for n = 32 and n = 24), registration and revocation incl. RA keys (ML-DSA-44 priced, HSS executed), ABI vs packed, corrected no-verification baseline, epoch test, model points with exact tokens and execution. Results in `onchain/results8/`.
- `offchain/lora_airtime.py`: LoRaWAN EU868 airtime, duty cycle and energy model.

## v2.4 (fourth self-review; arXiv v2)
- `PQAnchor4.sol`: sliding-window epochs and sequence numbers (192 values, same storage slot) so that reordered roots are accepted; batch leaves bind device, epoch and count; invalid devices are skipped instead of reverting the batch; registration nonce and PQ-authorized revocation; packed calldata path; no-verification baseline.
- `pq_gasbench5.mjs`, `enc_fix.mjs`: ABI vs packed encoding (with a check that no device or record was skipped), epoch reordering test, no-verification baseline, cost-model points, 40-signature LMS statistics. Results in `onchain/results5/`.
- `pq_gasbench6.mjs`: all main tables re-measured on the final contract (incl. ML-DSA-87). Results in `onchain/results6/`.
- `grind_lms.py`: RFC 8554 signer that grinds the randomizer to chosen Winternitz step counts; `lms_step_distribution.py`: exact step distribution for honest signers.

## v2.3 (third self-review)
- `LMSVerifier3.sol`: LMS/HSS for SHA-256 (n = 32) and SHA-256/192 (n = 24, SP 800-208); `test_lms3.mjs` checks valid, tampered and wrong-message inputs.
- `pq_gasbench4.mjs`: all device-root variants re-measured on `PQAnchor3` (relaxed epoch rule), with P-256 (EIP-7951) and hybrid ECDSA + ML-DSA-44 / Falcon-512 rows, LMS n = 24, and the LMS worst-case regression with R^2. Results in `onchain/results4/`.
- Device benchmark: liboqs C speed benchmark and OpenSSL P-256 (`offchain/results/speed_sig_c.txt`, `pq_device_c.csv`).
- Figures 2-4 regenerated (Fig. 3 from the replay-protected contract).

## v2.2 (second self-review)
- `PQAnchor3.sol`: per-record signatures with per-device sequence numbers (replay protection); epochs only need to increase (a withheld root no longer blocks later ones).
- `LMSVerifier2.sol`: LMS of any height (H5-H25) and two-level HSS, executed for real; worst-case verification derived from a regression on Winternitz chain steps.
- `pq_gasbench3.mjs`, `pr_warm.mjs`: per-record measurements on the revised contract in steady state; LMS-H15 and HSS; worst-case regression. Results in `onchain/results3/`.
- `scripts/stateful_bench.sh`: LMS/HSS/XMSS key generation, signing and verification in C (liboqs); results in `offchain/results-stateful/`.

## v2.1
- Device benchmark results from GitHub-hosted runners (ARM64 Neoverse N2, x86-64 Xeon Platinum 8370C) in `offchain/results-github/`; the workflow now also runs on pushes to the benchmark files.

## v2 (major revision)
- New contract `PQAnchor2.sol`: replay-protected device-signed roots (epoch per device), leaf-free (DR-0) and leaf-posting (DR-L) variants, keys in calldata or stored on-chain (DR-0C, incl. EIP-8051 expanded keys), post-quantum-authorized registration, domain-separated Merkle nodes.
- New `LMSVerifier.sol`: RFC 8554 LMS verification in Solidity, executed for real (W = 2, 4, 8).
- Empirical validation of the verification-cost substitution (`validate_exact.mjs`): +0.07%.
- Device benchmark: Keccak-256 Merkle tree matching the contract; interquartile ranges.
- Figures regenerated (Fig. 4 now compares each design with ECDSA in the same design).

## v1
- Initial release: device-side benchmark, per-record and device-root designs (`PQAnchor.sol`), transaction harness.
