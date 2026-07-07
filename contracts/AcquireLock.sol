// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AcquireLock {
    uint256 public nonce;

    event Locked(
        address indexed from,
        address indexed destination,
        uint256 amount,
        uint256 nonce
    );

    function lock(address destination) external payable {
        require(msg.value > 0, "AcquireLock: zero value");
        nonce++;
        emit Locked(msg.sender, destination, msg.value, nonce);
    }
}
