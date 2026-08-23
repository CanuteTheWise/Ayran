// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

/// Planted root cause: reentrancy. withdraw() calls the receiver before
/// zeroing balances (checks-effects-interactions inverted).
contract MiniVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send");
        balances[msg.sender] = 0;
    }
}
