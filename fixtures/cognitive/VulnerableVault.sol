pragma solidity ^0.8.20;

contract VulnerableVault {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public unlockTime;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(block.timestamp >= unlockTime, "locked");
        require(balances[msg.sender] >= amount, "bal");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function setUnlock(uint256 t) external onlyOwner {
        unlockTime = t;
    }
}
