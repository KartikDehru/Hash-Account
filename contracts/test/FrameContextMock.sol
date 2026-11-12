// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// TEST ONLY. Stands in for the EIP-8141 transaction context (TXPARAM, SIGPARAM, SIGDATACOPY)
/// for the test build of the account (LamportAccountMock.yul). It is not a network result.
contract FrameContextMock {
    mapping(uint256 => uint256) public txparam;
    mapping(uint256 => mapping(uint256 => uint256)) public sigparam;
    mapping(uint256 => bytes) internal sigdata;

    function setTx(uint256 p, uint256 v) external {
        txparam[p] = v;
    }

    function setSig(uint256 i, uint256 scheme, bytes calldata data) external {
        sigparam[i][1] = scheme;
        sigparam[i][3] = data.length;
        sigdata[i] = data;
    }

    fallback(bytes calldata data) external returns (bytes memory) {
        (uint256 sel, uint256 x, uint256 y) = abi.decode(data, (uint256, uint256, uint256));
        if (sel == 1) return abi.encode(txparam[x]);
        if (sel == 2) return abi.encode(sigparam[x][y]);
        if (sel == 3) return sigdata[x];
        revert("unknown context call");
    }
}
