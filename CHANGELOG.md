# Changelog

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
