// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AcquireLock {
    uint256 public nonce;

    event Locked(
        address indexed from,
        address indexed destination,
        uint256 amount,
        uint256 nonce,
        uint256 destinationChainId
    );

    function lock(address destination, uint256 destinationChainId) external payable {
        require(msg.value > 0, "AcquireLock: zero value");
        require(destinationChainId > 0, "AcquireLock: invalid chain ID");
        nonce++;
        emit Locked(msg.sender, destination, msg.value, nonce, destinationChainId);
    }
}
