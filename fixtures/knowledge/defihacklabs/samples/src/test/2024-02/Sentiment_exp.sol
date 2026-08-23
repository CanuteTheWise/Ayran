// Reconstructed card: attacker-only labels, USD-denominated loss, multi-line
// root-cause prose, and an && shell chain in the build note (sanitizer probe).
// Build note: npm install && npm run test
// Attack Tx: 0x1e2d3c4b5a69788796a5b4c3d2e1f0091827364554637281900a1b2c3d4e5f60
// EXPLOIT_BLOCK: 19288234
// Attacker EOA: 0x4c1b2d3e4f5061728394a5b6c7d8e9f01a2b3c4d
// Loss: 1_000_000 USD
// Root cause: account-liquidation path skipped solvency revalidation,
//   so undercollateralized accounts could borrow sequentially across
//   the shared lending pool.
contract Sentiment_exp {
    uint256 constant EXPLOIT_BLOCK = 19288234;

    function testExploit() public {
        vm.roll(EXPLOIT_BLOCK - 1);
        vm.startPrank(attacker, attacker);
        assertApproxEqAbs(drain, 950_000 ether, 1e6);
        vm.stopPrank();
    }
}
