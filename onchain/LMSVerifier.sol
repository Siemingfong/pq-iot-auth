// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title LMSVerifier: RFC 8554 LMS / LM-OTS verification (SHA-256, n = m = 32)
/// @notice Called with the EIP-8355-style layout  pk || sig || msg32  and returns 32 bytes = 1 on
///         success (reverts otherwise). Supports LMS_SHA256_M32_H5..H25 and LMOTS_SHA256_N32_W1..W8.
///         Hashing uses the SHA-256 precompile (0x02). Research code, not audited.
contract LMSVerifier {
    uint16 internal constant D_PBLC = 0x8080;
    uint16 internal constant D_MESG = 0x8181;
    uint16 internal constant D_LEAF = 0x8282;
    uint16 internal constant D_INTR = 0x8383;

    function _lmsH(uint32 t) internal pure returns (uint256) {
        if (t == 5) return 5; if (t == 6) return 10; if (t == 7) return 15; if (t == 8) return 20; if (t == 9) return 25;
        revert("lms type");
    }

    function _ots(uint32 t) internal pure returns (uint256 w, uint256 p, uint256 ls) {
        if (t == 1) return (1, 265, 7); if (t == 2) return (2, 133, 6); if (t == 3) return (4, 67, 4); if (t == 4) return (8, 34, 0);
        revert("ots type");
    }

    function _sha(bytes memory b) internal view returns (bytes32 r) {
        assembly ("memory-safe") {
            if iszero(staticcall(gas(), 0x02, add(b, 32), mload(b), 0x00, 32)) { revert(0, 0) }
            r := mload(0x00)
        }
    }

    /// digit i (w bits) of the 34-byte string Q || Cksm(Q)
    function _coef(bytes memory s, uint256 i, uint256 w) internal pure returns (uint256) {
        uint256 b = uint8(s[(i * w) / 8]);
        uint256 shift = 8 - (w * (i % (8 / w)) + w);
        return (b >> shift) & ((1 << w) - 1);
    }

    fallback(bytes calldata input) external returns (bytes memory) {
        uint32 lmsType = uint32(bytes4(input[0:4]));
        uint32 otsType = uint32(bytes4(input[4:8]));
        bytes16 I = bytes16(input[8:24]);
        bytes32 T1 = bytes32(input[24:56]);
        uint256 h = _lmsH(lmsType);
        (uint256 w, uint256 p, uint256 ls) = _ots(otsType);
        uint256 sigLen = 44 + p * 32 + h * 32;
        require(input.length == 56 + sigLen + 32, "len");
        bytes calldata sig = input[56:56 + sigLen];
        bytes32 m = bytes32(input[56 + sigLen:56 + sigLen + 32]);
        uint32 q = uint32(bytes4(sig[0:4]));
        require(uint32(bytes4(sig[4:8])) == otsType, "ots");
        require(uint32(bytes4(sig[40 + p * 32:44 + p * 32])) == lmsType, "lms");
        require(q < (1 << h), "q");

        // ---- LM-OTS: candidate public key Kc (RFC 8554, Algorithm 4b)
        bytes memory Qc = abi.encodePacked(_sha(abi.encodePacked(I, q, D_MESG, bytes32(sig[8:40]), m)), uint16(0));
        {
            uint256 sum = 0; uint256 u = 256 / w; uint256 mx = (1 << w) - 1;
            for (uint256 i = 0; i < u; i++) sum += mx - _coef(Qc, i, w);
            sum <<= ls;
            Qc[32] = bytes1(uint8(sum >> 8)); Qc[33] = bytes1(uint8(sum));
        }
        bytes memory zbuf = new bytes(22 + p * 32);          // I || q || D_PBLC || z_0 .. z_{p-1}
        bytes memory cb = new bytes(55);                       // I || q || i || j || tmp
        assembly ("memory-safe") {
            mstore(add(zbuf, 32), I) mstore(add(zbuf, 48), shl(224, q)) mstore(add(zbuf, 52), shl(240, D_PBLC))
            mstore(add(cb, 32), I) mstore(add(cb, 48), shl(224, q))
        }
        uint256 top = (1 << w) - 1;
        for (uint256 i = 0; i < p; i++) {
            uint256 a = _coef(Qc, i, w);
            bytes32 tmp = bytes32(sig[40 + i * 32:72 + i * 32]);
            assembly ("memory-safe") { mstore8(add(cb, 52), shr(8, i)) mstore8(add(cb, 53), and(i, 0xff)) }
            for (uint256 j = a; j < top; j++) {
                assembly ("memory-safe") {
                    mstore8(add(cb, 54), j)
                    mstore(add(cb, 55), tmp)
                    if iszero(staticcall(gas(), 0x02, add(cb, 32), 55, 0x00, 32)) { revert(0, 0) }
                    tmp := mload(0x00)
                }
            }
            assembly ("memory-safe") { mstore(add(add(zbuf, 54), mul(i, 32)), tmp) }
        }
        bytes32 node = _sha(abi.encodePacked(I, uint32((1 << h) + q), D_LEAF, _sha(zbuf)));

        // ---- LMS: authentication path (Algorithm 6a)
        uint256 nn = (1 << h) + q;
        uint256 off = 44 + p * 32;
        for (uint256 i = 0; i < h; i++) {
            bytes32 sib = bytes32(sig[off + i * 32:off + i * 32 + 32]);
            node = (nn & 1) == 1
                ? _sha(abi.encodePacked(I, uint32(nn >> 1), D_INTR, sib, node))
                : _sha(abi.encodePacked(I, uint32(nn >> 1), D_INTR, node, sib));
            nn >>= 1;
        }
        require(node == T1, "sig");
        return abi.encode(uint256(1));
    }
}

/// Measures the gas of one external call to a verifier, the way the Foundry benchmarks do
/// (gasleft() around the call, verifier account cold, input already in memory).
contract Meter {
    function meter(address v, bytes calldata input) external returns (uint256 used, bool ok) {
        bytes memory buf = input;
        uint256 g = gasleft();
        (ok,) = v.staticcall(buf);
        used = g - gasleft();
    }
}
