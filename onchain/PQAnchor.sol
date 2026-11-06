// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title PQAnchor: authentication and anchoring of IoT records with large signatures
/// @notice Two designs:
///   PR  (per-record)  every record carries its own signature, verified on-chain;
///   DR  (device-root) each device hashes its k records into a Merkle tree and signs only the
///                     root; the contract recomputes the root from the k leaves and verifies one
///                     signature per device.
///   Signatures are verified either by ecrecover (classical baseline, real) or by a call to the
///   verifier address VERIFIER with the EIP-8355 input layout pk || sig || msg32. In the gas
///   harness VERIFIER is an empty account, so the call carries the full input (memory and
///   calldata costs are real) but no verification work; the harness then adds the verification
///   gas of the implementation under study (Solidity verifier or proposed precompile).
contract PQAnchor {
    address public immutable kgc;
    address public immutable VERIFIER;
    mapping(uint32 => bytes32) public devCommit;      // keccak256(pk) or keccak256(address) for ECDSA
    mapping(bytes32 => uint256) public recordBlock;   // per-record anchoring
    mapping(bytes32 => uint256) public rootBlock;     // per-batch anchoring
    event BatchAnchored(bytes32 indexed root, uint256 n);

    struct Dev { uint32 idx; bytes pk; }                         // pk: PQ public key, or 20-byte address (ECDSA)
    struct Rec { uint16 dev; bytes32 ct; uint64 ts; bytes32 chk; bytes20 seed; bytes sig; }
    struct DevBatch { uint32 idx; bytes pk; bytes sig; bytes32[] leaves; }

    constructor(address verifier) { kgc = msg.sender; VERIFIER = verifier; }

    function registerDevice(uint32 idx, bytes calldata pk) external {
        require(msg.sender == kgc); devCommit[idx] = keccak256(pk);
    }

    // ------------------------------------------------------------------ helpers
    function _commit(uint32 idx, bytes calldata pk) internal view returns (bytes32 c) {
        c = devCommit[idx];
        require(c != bytes32(0) && c == keccak256(pk), "device");
    }

    /// ECDSA (65-byte r||s||v) when pk is a 20-byte address, otherwise the PQ verifier call.
    function _verify(bytes calldata pk, bytes calldata sig, bytes32 h) internal view {
        if (pk.length == 20) {
            bytes32 r = bytes32(sig[0:32]); bytes32 s = bytes32(sig[32:64]); uint8 v = uint8(sig[64]);
            require(ecrecover(h, v, r, s) == address(bytes20(pk)), "sig");
        } else {
            bytes memory input = abi.encodePacked(pk, sig, h);   // EIP-8355 layout
            (bool ok,) = VERIFIER.staticcall(input);
            require(ok, "verifier");
        }
    }

    function _merkle(bytes32[] memory h) internal pure returns (bytes32) {
        uint256 n = h.length;
        while (n > 1) {
            uint256 k = 0;
            for (uint256 i = 0; i < n; i += 2) h[k++] = (i + 1 < n) ? keccak256(abi.encodePacked(h[i], h[i + 1])) : h[i];
            n = k;
        }
        return h[0];
    }

    function _recHash(bytes32 c, Rec calldata r) internal view returns (bytes32) {
        return keccak256(abi.encode(address(this), c, r.ct, r.ts, r.chk, r.seed));
    }

    // ------------------------------------------------------------------ PR: per-record signatures
    function submitOne(Dev calldata d, Rec calldata r) external {
        bytes32 c = _commit(d.idx, d.pk);
        bytes32 h = _recHash(c, r);
        _verify(d.pk, r.sig, h);
        recordBlock[h] = block.number;
    }

    function submitPerRecord(Dev[] calldata ds, Rec[] calldata rs) external {
        bytes32[] memory cs = new bytes32[](ds.length);
        for (uint256 j = 0; j < ds.length; j++) cs[j] = _commit(ds[j].idx, ds[j].pk);
        bytes32[] memory leaves = new bytes32[](rs.length);
        for (uint256 i = 0; i < rs.length; i++) {
            Rec calldata r = rs[i];
            bytes32 h = _recHash(cs[r.dev], r);
            _verify(ds[r.dev].pk, r.sig, h);
            leaves[i] = h;
        }
        bytes32 root = _merkle(leaves);
        rootBlock[root] = block.number;
        emit BatchAnchored(root, rs.length);
    }

    // ------------------------------------------------------------------ DR: device-signed Merkle roots
    function submitDeviceRoots(DevBatch[] calldata bs) external {
        bytes32[] memory roots = new bytes32[](bs.length);
        uint256 n = 0;
        for (uint256 j = 0; j < bs.length; j++) {
            DevBatch calldata b = bs[j];
            bytes32 c = _commit(b.idx, b.pk);
            bytes32 dr = _merkle(b.leaves);                                   // copies leaves to memory
            _verify(b.pk, b.sig, keccak256(abi.encode(address(this), c, dr)));
            roots[j] = dr;
            n += b.leaves.length;
        }
        bytes32 root = _merkle(roots);
        rootBlock[root] = block.number;
        emit BatchAnchored(root, n);
    }
}
