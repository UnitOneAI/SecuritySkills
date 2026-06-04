// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UncheckedCallAirdrop {
    mapping(address => bool) public claimed;
    uint256 public rewardAmount = 0.01 ether;

    receive() external payable {}

    function claim() external {
        require(!claimed[msg.sender], "already claimed");

        msg.sender.call{value: rewardAmount}("");
        claimed[msg.sender] = true;
    }
}
