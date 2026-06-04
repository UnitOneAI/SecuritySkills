// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CheckedCallAirdrop {
    mapping(address => bool) public claimed;
    uint256 public rewardAmount = 0.01 ether;

    receive() external payable {}

    function claim() external {
        require(!claimed[msg.sender], "already claimed");
        claimed[msg.sender] = true;

        (bool ok, ) = msg.sender.call{value: rewardAmount}("");
        require(ok, "reward transfer failed");
    }
}
