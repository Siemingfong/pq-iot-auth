// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title PQAnchor2: device-signed Merkle roots with replay protection and on-chain keys
/// @notice Each device signs  M = keccak256(abi.encode(chainid, this, devCommit, idx, epoch, root, count)).
///   The contract enforces epoch = lastEpoch + 1 per device (no replay, no reordering).
///   Variants (per batch entry):
///     leaves.length > 0 : root recomputed from the posted leaves (count must match)   [DR-L]
///     leaves.length == 0: only the signed root is posted (leaf-free)                   [DR-0]
///     pk.length == 0    : public key read from on-chain code (SSTORE2) instead of calldata
///     pk.length == 20   : ECDSA (address), verified with ecrecover
///   Merkle nodes are domain-separated: node = keccak256(0x01 || left || right); devices compute
///   leaves as keccak256(0x00 || record). PQ signatures are checked by a call to VERIFIER with the
///   EIP-8355-style input pk || sig || M.
///   Registration: by the KGC's account (registerDevice / registerDeviceCode), or by anyone holding
///   a KGC post-quantum signature over the registration (registerDevicePQ).
contract PQAnchor2 {
    address public immutable kgc;
    address public immutable VERIFIER;
    address public kgcPqKey;                                // code pointer to the KGC's PQ public key
    mapping(uint32 => bytes32) public devCommit;            // keccak256(pk) (or of the address)
    mapping(uint32 => address) public devKeyCode;           // SSTORE2 pointer to pk, if stored on-chain
    mapping(uint32 => uint64) public lastEpoch;
    mapping(bytes32 => uint256) public rootBlock;
    event DeviceRoot(uint32 indexed idx, uint64 epoch, bytes32 root, uint32 count);

    struct Batch { uint32 idx; bytes pk; bytes sig; uint64 epoch; bytes32 root; uint32 count; bytes32[] leaves; }

    constructor(address verifier) { kgc = msg.sender; VERIFIER = verifier; }

    // ------------------------------------------------------------------ key storage
    function _store(bytes calldata data) internal returns (address ptr) {
        bytes memory code = abi.encodePacked(hex"63", uint32(data.length + 1), hex"80600e6000396000f300", data);
        assembly ("memory-safe") { ptr := create(0, add(code, 32), mload(code)) }
        require(ptr != address(0), "store");
    }

    function _load(address ptr) internal view returns (bytes memory out) {
        uint256 n;
        assembly ("memory-safe") { n := sub(extcodesize(ptr), 1) }
        out = new bytes(n);
        assembly ("memory-safe") { extcodecopy(ptr, add(out, 32), 1, n) }
    }

    function setKgcPqKey(bytes calldata pk) external { require(msg.sender == kgc && kgcPqKey == address(0)); kgcPqKey = _store(pk); }

    function registerDevice(uint32 idx, bytes calldata pk) external {
        require(msg.sender == kgc); devCommit[idx] = keccak256(pk);
    }

    function registerDeviceCode(uint32 idx, bytes calldata pk) external {
        require(msg.sender == kgc); devCommit[idx] = keccak256(pk); devKeyCode[idx] = _store(pk);
    }

    /// post-quantum registration: valid with a KGC PQ signature, independent of msg.sender
    function registerDevicePQ(uint32 idx, bytes calldata pk, bytes calldata kgcSig) external {
        require(devCommit[idx] == bytes32(0), "exists");
        bytes32 c = keccak256(pk);
        bytes32 m = keccak256(abi.encode(block.chainid, address(this), "register", idx, c));
        (bool ok,) = VERIFIER.staticcall(abi.encodePacked(_load(kgcPqKey), kgcSig, m));
        require(ok, "kgc sig");
        devCommit[idx] = c;
    }

    // ------------------------------------------------------------------ helpers
    function _merkle(bytes32[] memory h) internal pure returns (bytes32) {
        uint256 n = h.length;
        while (n > 1) {
            uint256 k = 0;
            for (uint256 i = 0; i < n; i += 2) h[k++] = (i + 1 < n) ? keccak256(abi.encodePacked(bytes1(0x01), h[i], h[i + 1])) : h[i];
            n = k;
        }
        return h[0];
    }

    function _verify(bytes memory pk, bytes calldata sig, bytes32 m) internal view {
        if (pk.length == 20) {
            bytes32 r = bytes32(sig[0:32]); bytes32 s = bytes32(sig[32:64]); uint8 v = uint8(sig[64]);
            require(ecrecover(m, v, r, s) == address(bytes20(pk)), "sig");
        } else {
            (bool ok,) = VERIFIER.staticcall(abi.encodePacked(pk, sig, m));
            require(ok, "verifier");
        }
    }

    // ------------------------------------------------------------------ device-signed roots
    function submit(Batch[] calldata bs) external {
        bytes32[] memory roots = new bytes32[](bs.length);
        for (uint256 j = 0; j < bs.length; j++) {
            Batch calldata b = bs[j];
            bytes32 c = devCommit[b.idx];
            bytes memory pk;
            if (b.pk.length == 0) pk = _load(devKeyCode[b.idx]);
            else { require(keccak256(b.pk) == c, "key"); pk = b.pk; }
            require(c != bytes32(0), "device");
            require(b.epoch == lastEpoch[b.idx] + 1, "epoch");
            lastEpoch[b.idx] = b.epoch;
            bytes32 root = b.root;
            if (b.leaves.length > 0) { require(b.leaves.length == b.count, "count"); root = _merkle(b.leaves); }
            _verify(pk, b.sig, keccak256(abi.encode(block.chainid, address(this), c, b.idx, b.epoch, root, b.count)));
            roots[j] = root;
            emit DeviceRoot(b.idx, b.epoch, root, b.count);
        }
        rootBlock[_merkle(roots)] = block.number;
    }
}
