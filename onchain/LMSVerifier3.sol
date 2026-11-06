// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title LMSVerifier3: RFC 8554 / SP 800-208 LMS and HSS verification, SHA-256 (n = 32) and SHA-256/192 (n = 24)
/// @notice Input layout pk || sig || msg32 (EIP-8355 style). pk of 56 bytes = LMS public key;
///         pk of 60 bytes = HSS public key (u32 L || LMS public key), L in {1, 2}.
///         Heights 5..25, Winternitz w in {1, 2, 4, 8}. Research code, not audited.
contract LMSVerifier3 {
    uint16 internal constant D_PBLC = 0x8080;
    uint16 internal constant D_MESG = 0x8181;
    uint16 internal constant D_LEAF = 0x8282;
    uint16 internal constant D_INTR = 0x8383;

    /// LMS type -> (height, n): 5..9 = SHA256_M32_H5..H25, 10..14 = SHA256_M24_H5..H25
    function _h(uint32 t) internal pure returns (uint256 h, uint256 n) {
        if (t >= 5 && t <= 9) return ((t - 4) * 5, 32);
        if (t >= 10 && t <= 14) return ((t - 9) * 5, 24);
        revert("lms type");
    }
    /// LM-OTS type -> (w, p, ls, n): 1..4 = SHA256_N32_W1..W8, 5..8 = SHA256_N24_W1..W8
    function _ots(uint32 t) internal pure returns (uint256 w, uint256 p, uint256 ls, uint256 n) {
        if (t == 1) return (1, 265, 7, 32); if (t == 2) return (2, 133, 6, 32); if (t == 3) return (4, 67, 4, 32); if (t == 4) return (8, 34, 0, 32);
        if (t == 5) return (1, 200, 8, 24); if (t == 6) return (2, 101, 6, 24); if (t == 7) return (4, 51, 4, 24); if (t == 8) return (8, 26, 0, 24);
        revert("ots type");
    }
    function _mask(uint256 n) internal pure returns (bytes32) { return n == 32 ? bytes32(type(uint256).max) : bytes32(~uint256((1 << (8 * (32 - n))) - 1)); }
    function _sha(bytes memory b) internal view returns (bytes32 r) {
        assembly ("memory-safe") {
            if iszero(staticcall(gas(), 0x02, add(b, 32), mload(b), 0x00, 32)) { revert(0, 0) }
            r := mload(0x00)
        }
    }
    function _coef(bytes memory s, uint256 i, uint256 w) internal pure returns (uint256) {
        return (uint256(uint8(s[(i * w) / 8])) >> (8 - (w * (i % (8 / w)) + w))) & ((1 << w) - 1);
    }

    /// length of an LMS signature starting at sig[0]
    function _sigLen(bytes calldata sig) internal pure returns (uint256) {
        (, uint256 p,, uint256 n) = _ots(uint32(bytes4(sig[4:8])));
        (uint256 h,) = _h(uint32(bytes4(sig[8 + n + p * n:12 + n + p * n])));
        return 12 + n + p * n + h * n;
    }

    /// RFC 8554 Algorithm 6a: verify an LMS signature on an arbitrary-length message
    function _lms(bytes calldata pk, bytes calldata sig, bytes memory m) internal view returns (bool) {
        uint32 lmsType = uint32(bytes4(pk[0:4]));
        uint32 otsType = uint32(bytes4(pk[4:8]));
        bytes16 I = bytes16(pk[8:24]);
        (uint256 h, uint256 n) = _h(lmsType);
        (uint256 w, uint256 p, uint256 ls, uint256 n2) = _ots(otsType);
        require(n == n2 && pk.length == 24 + n && sig.length == 12 + n + p * n + h * n, "len");
        uint32 q = uint32(bytes4(sig[0:4]));
        require(uint32(bytes4(sig[4:8])) == otsType && uint32(bytes4(sig[8 + n + p * n:12 + n + p * n])) == lmsType && q < (1 << h), "hdr");
        bytes32 mk = _mask(n);
        // Q || Cksm(Q), Q truncated to n bytes
        bytes memory Qc = new bytes(n + 2);
        {
            bytes32 Q = _sha(abi.encodePacked(I, q, D_MESG, sig[8:8 + n], m)) & mk;
            assembly ("memory-safe") { mstore(add(Qc, 32), Q) }
            uint256 sum = 0; uint256 mx = (1 << w) - 1;
            for (uint256 i = 0; i < (8 * n) / w; i++) sum += mx - _coef(Qc, i, w);
            sum <<= ls; Qc[n] = bytes1(uint8(sum >> 8)); Qc[n + 1] = bytes1(uint8(sum));
        }
        bytes memory zbuf = new bytes(22 + p * n + 32);          // +32 slack: z_i written as full words
        bytes memory cb = new bytes(55);                         // I || q || i || j || tmp (23 + n bytes hashed)
        assembly ("memory-safe") {
            mstore(add(zbuf, 32), I) mstore(add(zbuf, 48), shl(224, q)) mstore(add(zbuf, 52), shl(240, D_PBLC))
            mstore(add(cb, 32), I) mstore(add(cb, 48), shl(224, q))
        }
        uint256 top = (1 << w) - 1;
        uint256 cbl = 23 + n;
        for (uint256 i = 0; i < p; i++) {
            uint256 a = _coef(Qc, i, w);
            bytes32 tmp = bytes32(sig[8 + n + i * n:8 + 2 * n + i * n]) & mk;
            assembly ("memory-safe") { mstore8(add(cb, 52), shr(8, i)) mstore8(add(cb, 53), and(i, 0xff)) }
            for (uint256 j = a; j < top; j++) {
                assembly ("memory-safe") {
                    mstore8(add(cb, 54), j)
                    mstore(add(cb, 55), tmp)
                    if iszero(staticcall(gas(), 0x02, add(cb, 32), cbl, 0x00, 32)) { revert(0, 0) }
                    tmp := and(mload(0x00), mk)
                }
            }
            assembly ("memory-safe") { mstore(add(add(zbuf, 54), mul(i, n)), tmp) }
        }
        assembly ("memory-safe") { mstore(zbuf, add(22, mul(p, n))) }   // hash exactly 22 + p n bytes
        bytes32 node;
        {
            bytes32 Kc = _sha(zbuf) & mk;
            bytes memory lb = new bytes(22 + n + 32);
            assembly ("memory-safe") {
                mstore(add(lb, 32), I) mstore(add(lb, 48), shl(224, add(shl(h, 1), q))) mstore(add(lb, 52), shl(240, D_LEAF)) mstore(add(lb, 54), Kc)
                mstore(lb, add(22, n))
            }
            node = _sha(lb) & mk;
        }
        uint256 nn = (1 << h) + q;
        uint256 off = 12 + n + p * n;
        bytes memory ib = new bytes(22 + 2 * n + 32);
        assembly ("memory-safe") { mstore(add(ib, 32), I) mstore(add(ib, 52), shl(240, D_INTR)) mstore(ib, add(22, mul(2, n))) }
        for (uint256 i = 0; i < h; i++) {
            bytes32 sib = bytes32(sig[off + i * n:off + i * n + n]) & mk;
            uint256 par = nn >> 1;
            assembly ("memory-safe") {
                mstore(add(ib, 48), or(shl(224, par), and(mload(add(ib, 48)), 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff)))
                mstore(add(ib, 52), shl(240, D_INTR))
            }
            if ((nn & 1) == 1) { assembly ("memory-safe") { mstore(add(ib, 54), sib) mstore(add(add(ib, 54), n), node) } }
            else               { assembly ("memory-safe") { mstore(add(ib, 54), node) mstore(add(add(ib, 54), n), sib) } }
            node = _sha(ib) & mk;
            nn = par;
        }
        return node == (bytes32(pk[24:24 + n]) & mk);
    }

    fallback(bytes calldata input) external returns (bytes memory) {
        bytes calldata rest;
        bytes32 m = bytes32(input[input.length - 32:]);
        if (uint32(bytes4(input[0:4])) >= 5) {                  // plain LMS public key (type code first)
            (, uint256 n) = _h(uint32(bytes4(input[0:4])));
            bytes calldata pk = input[0:24 + n];
            rest = input[24 + n:input.length - 32];
            require(_lms(pk, rest, abi.encodePacked(m)), "sig");
        } else {                                                // HSS: u32 L || top-level LMS public key
            uint32 L = uint32(bytes4(input[0:4]));
            (, uint256 n0) = _h(uint32(bytes4(input[4:8])));
            bytes calldata pk = input[4:28 + n0];
            rest = input[28 + n0:input.length - 32];
            require(L >= 1 && L <= 2 && uint32(bytes4(rest[0:4])) == L - 1, "hss");
            uint256 o = 4;
            if (L == 2) {
                uint256 sl = _sigLen(rest[o:]);
                (, uint256 nc) = _h(uint32(bytes4(rest[o + sl:o + sl + 4])));
                bytes calldata childPk = rest[o + sl:o + sl + 24 + nc];
                require(_lms(pk, rest[o:o + sl], childPk), "hss top");
                pk = childPk; o += sl + 24 + nc;
            }
            require(_lms(pk, rest[o:], abi.encodePacked(m)), "sig");
        }
        return abi.encode(uint256(1));
    }
}

contract Meter {
    function meter(address v, bytes calldata input) external returns (uint256 used, bool ok) {
        bytes memory buf = input;
        uint256 g = gasleft();
        (ok,) = v.staticcall(buf);
        used = g - gasleft();
    }
}
