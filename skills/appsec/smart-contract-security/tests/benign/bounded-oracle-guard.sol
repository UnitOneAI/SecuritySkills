// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface GuardedPriceFeed {
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

    function decimals() external view returns (uint8);
}

contract BoundedOracleGuard {
    GuardedPriceFeed public immutable feed;
    uint256 public immutable heartbeat;
    uint256 public immutable minPrice;
    uint256 public immutable maxPrice;
    mapping(address => uint256) public minted;

    constructor(GuardedPriceFeed priceFeed, uint256 maxStaleness, uint256 minimumPrice, uint256 maximumPrice) {
        feed = priceFeed;
        heartbeat = maxStaleness;
        minPrice = minimumPrice;
        maxPrice = maximumPrice;
    }

    function mintAgainstEth() external payable {
        (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = feed.latestRoundData();
        require(answeredInRound >= roundId, "incomplete round");
        require(updatedAt != 0 && block.timestamp - updatedAt <= heartbeat, "stale price");
        require(answer > 0, "non-positive price");
        require(feed.decimals() == 8, "unexpected decimals");

        uint256 price = uint256(answer);
        require(price >= minPrice && price <= maxPrice, "price out of bounds");

        uint256 amount = (msg.value * price) / 1e8;
        minted[msg.sender] += amount;
    }
}
