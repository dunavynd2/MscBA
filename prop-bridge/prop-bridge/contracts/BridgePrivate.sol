// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BridgePrivate {
    address public deskAdmin;
    uint256 public sequenceNonce;

    event StrategySettled(
        address indexed trader,
        uint256 indexed nonce,
        uint256 assetAmount,
        bytes32 indexed destinationWallet
    );

    constructor() {
        deskAdmin = msg.sender;
    }

    function lockAssets(uint256 amount, bytes32 destinationWallet) external {
        sequenceNonce++;
        emit StrategySettled(msg.sender, sequenceNonce, amount, destinationWallet);
    }
}
