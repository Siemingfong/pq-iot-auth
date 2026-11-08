// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
/// Hybrid ECDSA + LMS verifier (AND combiner). Input, as sent by the anchor: pk || sig || m, where
///   pk  = LMS public key (56 bytes) || ECDSA address (20 bytes)
///   sig = LMS signature || ECDSA signature (r, s, v: 65 bytes)
///   m   = 32-byte message.
/// Both signatures cover the same m, and the key commitment covers both keys, so neither can be stripped.
contract HybridLMSVerifier {
    address public immutable LMS;
    constructor(address lms) { LMS = lms; }
    fallback(bytes calldata input) external returns (bytes memory) {
        uint256 n = input.length;
        require(n > 56 + 20 + 65 + 32, "len");
        bytes32 m = bytes32(input[n - 32:]);
        bytes calldata es = input[n - 97:n - 32];
        address a = address(bytes20(input[56:76]));
        require(ecrecover(m, uint8(es[64]), bytes32(es[0:32]), bytes32(es[32:64])) == a, "ecdsa");
        (bool ok,) = LMS.staticcall(abi.encodePacked(input[0:56], input[76:n - 97], m));
        require(ok, "lms");
        return "";
    }
}
