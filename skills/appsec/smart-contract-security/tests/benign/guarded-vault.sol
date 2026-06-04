// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GuardedVault {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        uint256 currentBalance = balances[msg.sender];
        require(currentBalance >= amount, "insufficient balance");

        balances[msg.sender] = currentBalance - amount;

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
