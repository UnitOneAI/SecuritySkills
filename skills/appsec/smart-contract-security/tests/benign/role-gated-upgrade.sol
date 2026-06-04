// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RoleGatedUpgrade {
    address public owner;
    address public implementation;

    event Upgraded(address indexed previousImplementation, address indexed newImplementation);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address initialImplementation) {
        require(initialImplementation != address(0), "zero implementation");
        owner = msg.sender;
        implementation = initialImplementation;
    }

    function upgradeTo(address newImplementation) external onlyOwner {
        require(newImplementation != address(0), "zero implementation");
        require(newImplementation.code.length > 0, "implementation has no code");

        address previousImplementation = implementation;
        implementation = newImplementation;

        emit Upgraded(previousImplementation, newImplementation);
    }
}
