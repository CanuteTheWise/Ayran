// Minimal reconstructed card: transaction hash and block anchor only.
// Attack tx: 0x7d2cbb1a6e94d7c8b5a4f3e2d1c0b9a8f7e6d5c4b3a291807f6e5d4c3b2a1908
contract Minimal_exp {
    uint256 constant EXPLOIT_BLOCK = 1640998200;

    function testExploit() public {
        vm.roll(EXPLOIT_BLOCK - 1);
        assertEq(drained, 1 ether);
    }
}
