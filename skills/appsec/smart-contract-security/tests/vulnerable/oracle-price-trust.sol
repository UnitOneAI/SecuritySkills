// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface PriceFeed {
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
}

contract OraclePriceTrust {
    PriceFeed public immutable feed;
    mapping(address => uint256) public minted;

    constructor(PriceFeed priceFeed) {
        feed = priceFeed;
    }

    function mintAgainstEth() external payable {
        (, int256 answer, , , ) = feed.latestRoundData();
        uint256 price = uint256(answer);
        uint256 amount = (msg.value * price) / 1e8;

        minted[msg.sender] += amount;
    }
}
