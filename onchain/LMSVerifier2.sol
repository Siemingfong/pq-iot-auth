// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title LMSVerifier2: RFC 8554 LMS and HSS verification (SHA-256, n = m = 32)
/// @notice Input layout pk || sig || msg32 (EIP-8355 style). pk of 56 bytes = LMS public key;
///         pk of 60 bytes = HSS public key (u32 L || LMS public key), L in {1, 2}.
///         Heights 5..25, Winternitz w in {1, 2, 4, 8}. Research code, not audited.
contract LMSVerifier2 {
    uint16 internal constant D_PBLC = 0x8080;
    uint16 internal constant D_MESG = 0x8181;
    uint16 internal constant D_LEAF = 0x8282;
    uint16 internal constant D_INTR = 0x8383;

    function _h(uint32 t) internal pure returns (uint256) {
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
    function _coef(bytes memory s, uint256 i, uint256 w) internal pure returns (uint256) {
        return (uint256(uint8(s[(i * w) / 8])) >> (8 - (w * (i % (8 / w)) + w))) & ((1 << w) - 1);
    }

    /// length of an LMS signature starting at sig[0]
    function _sigLen(bytes calldata sig) internal pure returns (uint256) {
        (, uint256 p,) = _ots(uint32(bytes4(sig[4:8])));
        return 44 + p * 32 + _h(uint32(bytes4(sig[40 + p * 32:44 + p * 32]))) * 32;
    }

    /// RFC 8554 Algorithm 6a: verify an LMS signature on an arbitrary-length message
    function _lms(bytes calldata pk, bytes calldata sig, bytes memory m) internal view returns (bool) {
        uint32 lmsType = uint32(bytes4(pk[0:4]));
        uint32 otsType = uint32(bytes4(pk[4:8]));
        bytes16 I = bytes16(pk[8:24]);
        uint256 h = _h(lmsType);
        (uint256 w, uint256 p, uint256 ls) = _ots(otsType);
        require(sig.length == 44 + p * 32 + h * 32, "len");
        uint32 q = uint32(bytes4(sig[0:4]));
        require(uint32(bytes4(sig[4:8])) == otsType && uint32(bytes4(sig[40 + p * 32:44 + p * 32])) == lmsType && q < (1 << h), "hdr");
        bytes memory Qc = abi.encodePacked(_sha(abi.encodePacked(I, q, D_MESG, bytes32(sig[8:40]), m)), uint16(0));
        {
            uint256 sum = 0; uint256 mx = (1 << w) - 1;
            for (uint256 i = 0; i < 256 / w; i++) sum += mx - _coef(Qc, i, w);
            sum <<= ls; Qc[32] = bytes1(uint8(sum >> 8)); Qc[33] = bytes1(uint8(sum));
        }
        bytes memory zbuf = new bytes(22 + p * 32);
        bytes memory cb = new bytes(55);
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
        uint256 nn = (1 << h) + q;
        uint256 off = 44 + p * 32;
        for (uint256 i = 0; i < h; i++) {
            bytes32 sib = bytes32(sig[off + i * 32:off + i * 32 + 32]);
            node = (nn & 1) == 1 ? _sha(abi.encodePacked(I, uint32(nn >> 1), D_INTR, sib, node))
                                 : _sha(abi.encodePacked(I, uint32(nn >> 1), D_INTR, node, sib));
            nn >>= 1;
        }
        return node == bytes32(pk[24:56]);
    }

    fallback(bytes calldata input) external returns (bytes memory) {
        bytes calldata rest;
        bytes32 m = bytes32(input[input.length - 32:]);
        if (uint32(bytes4(input[0:4])) >= 5) {                  // plain LMS public key (type code first)
            bytes calldata pk = input[0:56];
            rest = input[56:input.length - 32];
            require(_lms(pk, rest, abi.encodePacked(m)), "sig");
        } else {                                                // HSS: u32 L || top-level LMS public key
            uint32 L = uint32(bytes4(input[0:4]));
            bytes calldata pk = input[4:60];
            rest = input[60:input.length - 32];
            require(L >= 1 && L <= 2 && uint32(bytes4(rest[0:4])) == L - 1, "hss");
            uint256 o = 4;
            if (L == 2) {
                uint256 sl = _sigLen(rest[o:]);
                bytes calldata childPk = rest[o + sl:o + sl + 56];
                require(_lms(pk, rest[o:o + sl], childPk), "hss top");
                pk = childPk; o += sl + 56;
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
