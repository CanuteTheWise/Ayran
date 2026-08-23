// Irregular neighbor: month directory 2022-13 is not a valid month.
// Attack tx: 0x0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9
contract BadMonth_exp {
    function testExploit() public {
        assertEq(1, 1);
    }
}
