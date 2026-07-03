// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @notice Release tokens on the destination chain when the relay submits a valid lock proof.
/// Exactly-once delivery is enforced by the processed mapping keyed on (sourceChainId, lockNonce).
contract BridgeRelease is ReentrancyGuard, Ownable {
    /// @notice The authorised relay address — set at deploy time and immutable.
    address public immutable relay;

    /// @notice (sourceChainId, lockNonce) → released. Prevents replay attacks across different source chains.
    mapping(uint256 => mapping(uint64 => bool)) public processed;

    event Release(
        address indexed recipient,
        uint256 amount,
        uint64 indexed lockNonce,
        uint256 indexed sourceChainId
    );
    event Fund(address indexed from, uint256 amount);

    error AlreadyProcessed(uint256 sourceChainId, uint64 nonce);
    error Unauthorized();
    error ReleaseFailed();
    error InsufficientBalance();

    constructor(address _relay, address initialOwner) Ownable(initialOwner) {
        require(_relay != address(0), "BridgeRelease: zero relay");
        relay = _relay;
    }

    /// @notice Release tokens to recipient. Only callable by the relay.
    /// @param recipient Address to receive tokens on this chain.
    /// @param amount Must match the locked amount on the source chain.
    /// @param lockNonce Nonce from BridgeLock.Lock — enforces exactly-once delivery.
    /// @param sourceChainId The chain ID where tokens were locked.
    function release(
        address payable recipient,
        uint256 amount,
        uint64 lockNonce,
        uint256 sourceChainId
    ) external nonReentrant {
        if (msg.sender != relay) revert Unauthorized();
        if (processed[sourceChainId][lockNonce]) revert AlreadyProcessed(sourceChainId, lockNonce);
        if (address(this).balance < amount) revert InsufficientBalance();

        processed[sourceChainId][lockNonce] = true;

        (bool ok,) = recipient.call{value: amount}("");
        if (!ok) revert ReleaseFailed();

        emit Release(recipient, amount, lockNonce, sourceChainId);
    }

    /// @notice Fund the release liquidity pool.
    function fund() external payable {
        emit Fund(msg.sender, msg.value);
    }

    receive() external payable {
        emit Fund(msg.sender, msg.value);
    }
}
