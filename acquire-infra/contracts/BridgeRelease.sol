// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @notice Release native tokens on the destination chain.
/// Called by the owner (or a relay) after a corresponding Lock event on the source chain.
/// Replay protection is enforced via the processed mapping keyed on lockNonce.
contract BridgeRelease is ReentrancyGuard, Ownable {
    /// @notice lockNonce => released. Prevents replay.
    mapping(uint64 => bool) public processed;

    event Release(
        address indexed recipient,
        uint256 amount,
        uint64  indexed lockNonce,
        uint256 sourceChainId
    );
    event Fund(address indexed from, uint256 amount);
    event Sweep(address indexed to, uint256 amount);

    error AlreadyProcessed(uint64 nonce);
    error ReleaseFailed();
    error InsufficientBalance();

    constructor(address initialOwner) Ownable(initialOwner) {}

    /// @notice Release tokens to recipient. Only callable by the owner.
    /// @param recipient    Address to receive tokens on this chain.
    /// @param amount       Must match the locked amount on the source chain (in wei).
    /// @param lockNonce    Nonce from BridgeLock.Lock — enforces exactly-once delivery.
    /// @param sourceChainId Chain ID where the corresponding Lock was emitted.
    function release(
        address payable recipient,
        uint256 amount,
        uint64  lockNonce,
        uint256 sourceChainId
    ) external onlyOwner nonReentrant {
        if (processed[lockNonce]) revert AlreadyProcessed(lockNonce);
        if (address(this).balance < amount) revert InsufficientBalance();

        processed[lockNonce] = true;

        (bool ok,) = recipient.call{value: amount}("");
        if (!ok) revert ReleaseFailed();

        emit Release(recipient, amount, lockNonce, sourceChainId);
    }

    /// @notice Emergency drain — owner only.
    function sweep(address payable to) external onlyOwner {
        uint256 bal = address(this).balance;
        require(bal > 0, "BridgeRelease: empty");
        (bool ok,) = to.call{value: bal}("");
        require(ok, "BridgeRelease: sweep failed");
        emit Sweep(to, bal);
    }

    /// @notice Fund the release liquidity pool.
    function fund() external payable {
        emit Fund(msg.sender, msg.value);
    }

    receive() external payable {
        emit Fund(msg.sender, msg.value);
    }
}
