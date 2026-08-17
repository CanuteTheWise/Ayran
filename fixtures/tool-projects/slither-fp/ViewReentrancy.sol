pragma solidity ^0.8.20;

interface IOracle {
    function latest() external view returns (uint256);
}

/// Classic Slither false positive: a view function that "calls" an external
/// view cannot reenter with state mutation, but reentrancy detectors still fire.
contract ViewReentrancy {
    IOracle public oracle;

    constructor(IOracle oracle_) {
        oracle = oracle_;
    }

    function peek() external view returns (uint256) {
        return oracle.latest();
    }
}
