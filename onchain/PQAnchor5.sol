// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title PQAnchor5: anchoring IoT records with device signatures (research code, not audited)
/// @notice PQAnchor5 = PQAnchor4 with Merkle hashing in place (no memory growth per hash), leaves copied
///   with calldatacopy in the packed path, P-256 verified for real through the EIP-7951 precompile
///   (64-byte keys), and no key load in the no-verification modes.
/// @notice Changes over PQAnchor3:
///  - Epochs/sequence numbers: either strictly increasing (WINDOW = false) or accepted within a
///    sliding window of 192 values (WINDOW = true): a root for epoch e is accepted if e is above the
///    highest accepted epoch, or within the 192 epochs below it and not yet used. High mark and bitmap
///    share one storage slot, so reordered submissions are accepted at the same storage cost.
///  - The batch tree commits to device identity: batch leaf = keccak256(0x02 || idx || e || k || R).
///  - An invalid device signature skips that device (event DeviceRejected) instead of reverting.
///  - Registration messages carry a per-index nonce; revocation is authorized by the RA's PQ key.
///  - A packed calldata path (fallback) next to the ABI path, with identical signed messages.
///  - Mode NOVERIFY anchors roots and signatures without verifying them (baseline).
contract PQAnchor5 {
    address public immutable ra;
    address public immutable VERIFIER;
    bool public immutable WINDOW;
    address public raPqKey;
    mapping(uint32 => bytes32) public devCommit;
    mapping(uint32 => address) public devKeyCode;
    mapping(uint32 => uint256) public epochState;   // high (64 bits) << 192 | bitmap (192 bits)
    mapping(uint32 => uint256) public seqState;     // same layout, per-record sequence numbers
    mapping(uint32 => uint64) public regNonce;
    mapping(bytes32 => uint256) public rootBlock;
    event DeviceRoot(uint32 indexed idx, uint64 epoch, bytes32 root, uint32 count);
    event DeviceRejected(uint32 indexed idx, uint64 epoch);

    struct Batch { uint32 idx; bytes pk; bytes sig; uint64 epoch; bytes32 root; uint32 count; bytes32[] leaves; }
    struct Rec { bytes32 ct; uint64 ts; bytes32 chk; bytes20 seed; bytes sig; }
    struct PRBatch { uint32 idx; bytes pk; uint64 seqStart; Rec[] recs; }

    constructor(address verifier, bool window) { ra = msg.sender; VERIFIER = verifier; WINDOW = window; }

    // ------------------------------------------------------------------ epochs
    /// returns the new state, or 0 if e is not acceptable
    function _accept(uint256 st, uint64 e) internal view returns (uint256) {
        uint64 high = uint64(st >> 192);
        uint256 bm = st & ((uint256(1) << 192) - 1);
        if (e > high) {
            if (!WINDOW) return uint256(e) << 192;
            uint256 d = e - high;
            uint256 nb = d >= 192 ? 0 : ((bm << d) | (high == 0 ? 0 : (uint256(1) << (d - 1)))) & ((uint256(1) << 192) - 1);
            return (uint256(e) << 192) | nb;
        }
        if (!WINDOW || e == high || high - e > 192 || e == 0) return 0;
        uint256 bit = uint256(1) << (high - e - 1);
        if (bm & bit != 0) return 0;
        return st | bit;
    }

    // ------------------------------------------------------------------ keys and registration
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
    function setRaPqKey(bytes calldata pk) external { require(msg.sender == ra && raPqKey == address(0)); raPqKey = _store(pk); }
    function registerDevice(uint32 idx, bytes calldata pk) external { require(msg.sender == ra); devCommit[idx] = keccak256(pk); }
    function registerDeviceCode(uint32 idx, bytes calldata pk) external { require(msg.sender == ra); devCommit[idx] = keccak256(pk); devKeyCode[idx] = _store(pk); }
    /// RA-signed registration over (chainid, this, "register", idx, H(pk), nonce); the nonce prevents
    /// re-registering a revoked key by replaying an old authorization.
    function registerDevicePQ(uint32 idx, bytes calldata pk, bytes calldata raSig) external {
        require(devCommit[idx] == bytes32(0), "exists");
        uint64 n = regNonce[idx];
        bytes32 m = keccak256(abi.encode(block.chainid, address(this), "register", idx, keccak256(pk), n));
        (bool ok,) = VERIFIER.staticcall(abi.encodePacked(_load(raPqKey), raSig, m));
        require(ok, "ra sig");
        devCommit[idx] = keccak256(pk); regNonce[idx] = n + 1;
    }
    function revokeDevicePQ(uint32 idx, bytes calldata raSig) external {
        uint64 n = regNonce[idx];
        bytes32 m = keccak256(abi.encode(block.chainid, address(this), "revoke", idx, devCommit[idx], n));
        (bool ok,) = VERIFIER.staticcall(abi.encodePacked(_load(raPqKey), raSig, m));
        require(ok, "ra sig");
        delete devCommit[idx]; delete devKeyCode[idx]; regNonce[idx] = n + 1;
    }

    // ------------------------------------------------------------------ helpers
    function _merkle(bytes32[] memory h, uint256 n) internal pure returns (bytes32 r) {
        if (n == 0) return bytes32(0);
        assembly ("memory-safe") {
            let buf := mload(0x40)                      // scratch: 0x01 || left || right (65 bytes), not allocated
            let base := add(h, 0x20)
            for {} gt(n, 1) {} {
                let k := 0
                for { let i := 0 } lt(i, n) { i := add(i, 2) } {
                    switch lt(add(i, 1), n)
                    case 1 {
                        mstore8(buf, 0x01)
                        mstore(add(buf, 1), mload(add(base, mul(i, 0x20))))
                        mstore(add(buf, 33), mload(add(base, mul(add(i, 1), 0x20))))
                        mstore(add(base, mul(k, 0x20)), keccak256(buf, 65))
                    }
                    default { mstore(add(base, mul(k, 0x20)), mload(add(base, mul(i, 0x20)))) }
                    k := add(k, 1)
                }
                n := k
            }
            r := mload(base)
        }
    }
    function _ok(bytes memory pk, bytes calldata sig, bytes32 m) internal view returns (bool) {
        if (pk.length == 64) {
            if (sig.length != 64) return false;
            (bool ok, bytes memory out) = address(0x100).staticcall(abi.encodePacked(m, sig, pk));
            return ok && out.length == 32 && uint256(bytes32(out)) == 1;
        }
        if (pk.length == 20) {
            if (sig.length != 65) return false;
            return ecrecover(m, uint8(sig[64]), bytes32(sig[0:32]), bytes32(sig[32:64])) == address(bytes20(pk));
        }
        (bool ok,) = VERIFIER.staticcall(abi.encodePacked(pk, sig, m));
        return ok;
    }
    function _msgDR(bytes32 c, uint32 idx, uint64 e, bytes32 root, uint32 k) internal view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), c, idx, e, root, k));
    }
    function _batchLeaf(uint32 idx, uint64 e, uint32 k, bytes32 root) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes1(0x02), idx, e, k, root));
    }

    // ------------------------------------------------------------------ device-signed roots (ABI)
    function submit(Batch[] calldata bs) external {
        bytes32[] memory bl = new bytes32[](bs.length);
        uint256 nb = 0;
        for (uint256 j = 0; j < bs.length; j++) {
            Batch calldata b = bs[j];
            bytes32 c = devCommit[b.idx];
            if (c == bytes32(0)) { emit DeviceRejected(b.idx, b.epoch); continue; }
            bytes memory pk = b.pk.length == 0 ? _load(devKeyCode[b.idx]) : b.pk;
            if (b.pk.length != 0 && keccak256(b.pk) != c) { emit DeviceRejected(b.idx, b.epoch); continue; }
            uint256 ns = _accept(epochState[b.idx], b.epoch);
            bytes32 root = b.root;
            if (b.leaves.length > 0) { if (b.leaves.length != b.count) { emit DeviceRejected(b.idx, b.epoch); continue; } root = _merkle(b.leaves, b.leaves.length); }
            if (ns == 0 || !_ok(pk, b.sig, _msgDR(c, b.idx, b.epoch, root, b.count))) { emit DeviceRejected(b.idx, b.epoch); continue; }
            epochState[b.idx] = ns;
            bl[nb++] = _batchLeaf(b.idx, b.epoch, b.count, root);
            emit DeviceRoot(b.idx, b.epoch, root, b.count);
        }
        if (nb > 0) rootBlock[_merkle(bl, nb)] = block.number;
    }

    // ------------------------------------------------------------------ per-record signatures (ABI)
    function submitPR(PRBatch[] calldata bs) external {
        uint256 n = 0;
        for (uint256 j = 0; j < bs.length; j++) n += bs[j].recs.length;
        bytes32[] memory leaves = new bytes32[](n);
        uint256 t = 0;
        for (uint256 j = 0; j < bs.length; j++) {
            PRBatch calldata b = bs[j];
            bytes32 c = devCommit[b.idx];
            if (c == bytes32(0) || keccak256(b.pk) != c) { emit DeviceRejected(b.idx, b.seqStart); continue; }
            uint256 st = seqState[b.idx];
            for (uint256 i = 0; i < b.recs.length; i++) {
                Rec calldata r = b.recs[i];
                uint256 ns = _accept(st, b.seqStart + uint64(i));
                bytes32 leaf = keccak256(abi.encodePacked(bytes1(0x00), abi.encode(r.ct, r.ts, r.chk, r.seed)));
                if (ns == 0 || !_ok(b.pk, r.sig, keccak256(abi.encode(block.chainid, address(this), c, b.idx, b.seqStart + uint64(i), leaf)))) {
                    emit DeviceRejected(b.idx, b.seqStart + uint64(i)); continue;
                }
                st = ns; leaves[t++] = leaf;
            }
            seqState[b.idx] = st;
        }
        if (t > 0) rootBlock[_merkle(leaves, t)] = block.number;
    }

    // ------------------------------------------------------------------ packed calldata path
    /// op 0x01, device roots:  mode(1) ndev(2) { idx(4) e(8) k(4) flags(1) [R(32) unless leaves]
    ///                         [pkLen(2) pk unless key on-chain] sigLen(2) sig [k x 32 leaves] }
    ///   flags: bit0 leaves posted, bit1 key on-chain. mode: 0 verify, 1 no verification (signature
    ///   posted), 2 no verification (only H(sig) posted in the sig field).
    /// op 0x02, per-record:    ndev(2) nrecTotal(4) { idx(4) s0(8) nrec(2) pkLen(2) pk { ct(32) ts(8) chk(32) seed(20) sigLen(2) sig } }
    fallback(bytes calldata d) external returns (bytes memory) {
        if (d[0] == 0x01) _packedDR(d); else if (d[0] == 0x02) _packedPR(d); else revert("op");
        return "";
    }

    function _packedDR(bytes calldata d) internal {
        uint8 mode = uint8(d[1]);
        uint256 ndev = uint16(bytes2(d[2:4]));
        uint256 o = 4;
        bytes32[] memory bl = new bytes32[](ndev);
        uint256 nb = 0;
        for (uint256 j = 0; j < ndev; j++) {
            uint32 idx = uint32(bytes4(d[o:o + 4])); uint64 e = uint64(bytes8(d[o + 4:o + 12])); uint32 k = uint32(bytes4(d[o + 12:o + 16]));
            uint8 fl = uint8(d[o + 16]); o += 17;
            bytes32 root;
            if (fl & 1 == 0) { root = bytes32(d[o:o + 32]); o += 32; }
            bytes memory pk; bytes32 c = devCommit[idx];
            if (fl & 2 != 0) { if (mode == 0) pk = _load(devKeyCode[idx]); }
            else { uint256 pl = uint16(bytes2(d[o:o + 2])); pk = d[o + 2:o + 2 + pl]; o += 2 + pl; }
            uint256 sl = uint16(bytes2(d[o:o + 2]));
            bytes calldata sig = d[o + 2:o + 2 + sl]; o += 2 + sl;
            if (fl & 1 != 0) {
                bytes32[] memory lv = new bytes32[](k);
                assembly ("memory-safe") { calldatacopy(add(lv, 0x20), add(d.offset, o), mul(k, 0x20)) }
                o += 32 * k; root = _merkle(lv, k);
            }
            uint256 ns = _accept(epochState[idx], e);
            bool good = c != bytes32(0) && ns != 0 && (fl & 2 != 0 || mode != 0 || keccak256(pk) == c);
            if (good && mode == 0) good = _ok(pk, sig, _msgDR(c, idx, e, root, k));
            if (!good) { emit DeviceRejected(idx, e); continue; }
            epochState[idx] = ns;
            bl[nb++] = _batchLeaf(idx, e, k, root);
            emit DeviceRoot(idx, e, root, k);
        }
        if (nb > 0) rootBlock[_merkle(bl, nb)] = block.number;
    }

    function _packedPR(bytes calldata d) internal {
        uint256 ndev = uint16(bytes2(d[1:3]));
        bytes32[] memory leaves = new bytes32[](uint32(bytes4(d[3:7])));
        uint256 o = 7;
        uint256 t = 0;
        for (uint256 j = 0; j < ndev; j++) {
            uint32 idx = uint32(bytes4(d[o:o + 4])); uint64 s0 = uint64(bytes8(d[o + 4:o + 12])); uint256 nr = uint16(bytes2(d[o + 12:o + 14]));
            uint256 pl = uint16(bytes2(d[o + 14:o + 16]));
            bytes memory pk = d[o + 16:o + 16 + pl]; o += 16 + pl;
            bytes32 c = devCommit[idx];
            bool keyOk = c != bytes32(0) && keccak256(pk) == c;
            uint256 st = seqState[idx];
            for (uint256 i = 0; i < nr; i++) {
                bytes32 leaf = keccak256(abi.encodePacked(bytes1(0x00), abi.encode(bytes32(d[o:o + 32]), uint64(bytes8(d[o + 32:o + 40])), bytes32(d[o + 40:o + 72]), bytes20(d[o + 72:o + 92]))));
                uint256 sl = uint16(bytes2(d[o + 92:o + 94]));
                bytes calldata sig = d[o + 94:o + 94 + sl]; o += 94 + sl;
                uint256 ns = _accept(st, s0 + uint64(i));
                if (!keyOk || ns == 0 || !_ok(pk, sig, keccak256(abi.encode(block.chainid, address(this), c, idx, s0 + uint64(i), leaf)))) { emit DeviceRejected(idx, s0 + uint64(i)); continue; }
                st = ns; leaves[t++] = leaf;
            }
            seqState[idx] = st;
        }
        if (t > 0) rootBlock[_merkle(leaves, t)] = block.number;
    }
}
