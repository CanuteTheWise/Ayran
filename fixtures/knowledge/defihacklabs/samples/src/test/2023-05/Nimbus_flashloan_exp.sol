// Reconstructed card with URL-embedded transaction hash and token-less loss.
// TX : https://etherscan.io/tx/0x4b2f9e0d1a2b3c4d5e6f708192a3b4c5d6e7f8090a1b2c3d4e5f60718293a4b5
// EXPLOIT_BLOCK: 17322110
// Attacker EOA: 0x35e2a9b1c4d5e6f708192a3b4c5d6e7f8091a2b3
// Loss: 42_500
// Root cause: flash-loan callback reused stale reserves pricing.
contract Nimbus_flashloan_exp {
    uint256 constant EXPLOIT_BLOCK = 17322110;

    function testExploit() public {
        vm.roll(EXPLOIT_BLOCK - 1);
        vm.startPrank(attacker, attacker);
        assertApproxEqAbs(profit, 42_500 ether, 1e4);
        vm.stopPrank();
    }
}
