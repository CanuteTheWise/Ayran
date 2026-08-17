pragma solidity ^0.8.20;

import {Counter} from "../src/Counter.sol";

contract CounterTest {
    function testPass() public {
        Counter counter = new Counter();
        counter.inc();
        require(counter.n() == 1, "expected n==1");
    }

    function testMismatch() public pure {
        require(uint256(1) == uint256(2), "assertion failed: 1 != 2");
    }
}
