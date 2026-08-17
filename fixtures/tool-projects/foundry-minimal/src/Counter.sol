pragma solidity ^0.8.20;

contract Counter {
    uint256 public n;

    function inc() external {
        n += 1;
    }
}
