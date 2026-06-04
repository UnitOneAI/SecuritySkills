// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UnguardedUpgrade {
    address public implementation;

    function upgradeTo(address newImplementation) external {
        implementation = newImplementation;
    }
}
