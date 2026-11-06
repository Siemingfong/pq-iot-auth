// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import "./LMSVerifier3.sol";
/// Test harness: HSS verification (any number of levels) on arbitrary-length messages, using the
/// same internal LMS routine as the deployed verifier. Used for RFC 8554 test vectors and fuzzing.
contract RFCTest is LMSVerifier3 {
    function verifyHSS(bytes calldata pub, bytes calldata sig, bytes calldata m) external view returns (bool) {
        uint32 L = uint32(bytes4(pub[0:4]));
        (, uint256 n0) = _h(uint32(bytes4(pub[4:8])));
        bytes calldata pk = pub[4:28 + n0];
        if (L == 0 || uint32(bytes4(sig[0:4])) != L - 1) return false;
        uint256 o = 4;
        for (uint32 i = 0; i + 1 < L; i++) {
            uint256 sl = _sigLen(sig[o:]);
            (, uint256 nc) = _h(uint32(bytes4(sig[o + sl:o + sl + 4])));
            bytes calldata child = sig[o + sl:o + sl + 24 + nc];
            if (!_lms(pk, sig[o:o + sl], child)) return false;
            pk = child; o += sl + 24 + nc;
        }
        return _lms(pk, sig[o:], m);
    }
}
