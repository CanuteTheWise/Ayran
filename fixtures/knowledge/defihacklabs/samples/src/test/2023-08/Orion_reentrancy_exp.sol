/*
 * Reconstructed block-comment card layout (format-faithful synthetic).
 * Attack Tx: 0x9c3b4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a
 * Overview: oracle price feed was manipulable via a single unguarded setter.
 * Attacker wallet: 0x7a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d
 * Victim contract: 0x8b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e
 * Amount: 3_000_000 DAI
 * EXPLOIT_BLOCK: 18120100
 */
contract Orion_reentrancy_exp {
    uint256 constant EXPLOIT_BLOCK = 18120100;

    function testExploit() public {
        vm.roll(EXPLOIT_BLOCK - 1);
        vm.startPrank(attacker, attacker);
        assertGt(gained, 2_900_000 ether, "oracle drain short");
        vm.stopPrank();
    }
}
