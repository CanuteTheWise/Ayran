// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

/// Planted root cause: share-inflation / donation attack.
/// Shares mint as amount * totalSupply / tokenBalance, so a donation that
/// inflates tokenBalance without minting shares dilutes the next depositor.
contract SharePool {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 public tokenBalance;

    function deposit(uint256 amount) external {
        uint256 minted = totalShares == 0 ? amount : (amount * totalShares) / tokenBalance;
        shares[msg.sender] += minted;
        totalShares += minted;
        tokenBalance += amount;
    }

    function donate(uint256 amount) external {
        tokenBalance += amount;
    }

    function redeem(uint256 shareAmount) external {
        uint256 payout = (shareAmount * tokenBalance) / totalShares;
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        tokenBalance -= payout;
    }
}
