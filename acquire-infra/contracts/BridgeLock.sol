// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @notice Lock native tokens on the source chain.
/// The Go relay watches for Lock events and calls BridgeRelease on the destination chain.
contract BridgeLock is ReentrancyGuard, Ownable {
    uint64 public lockNonce;

    event Lock(
        address indexed from,
        address indexed recipient,
        uint256 amount,
        uint64  nonce,
        uint256 destinationChainId
    );

    event Sweep(address indexed to, uint256 amount);

    constructor(address initialOwner) Ownable(initialOwner) {}

    /// @notice Lock msg.value to be released to recipient on the destination chain.
    /// @param recipient         Destination chain address to receive the released tokens.
    /// @param destinationChainId The chain ID where tokens should be released (e.g., 11155111 for Sepolia, 1 for Mainnet).
    function lock(address recipient, uint256 destinationChainId) external payable nonReentrant {
        require(msg.value > 0, "BridgeLock: zero value");
        require(recipient != address(0), "BridgeLock: zero recipient");
        require(destinationChainId > 0, "BridgeLock: invalid chain ID");
        uint64 nonce = lockNonce++;
        emit Lock(msg.sender, recipient, msg.value, nonce, destinationChainId);
    }

    /// @notice Emergency drain — owner only.
    function sweep(address payable to) external onlyOwner {
        uint256 bal = address(this).balance;
        require(bal > 0, "BridgeLock: empty");
        (bool ok,) = to.call{value: bal}("");
        require(ok, "BridgeLock: sweep failed");
        emit Sweep(to, bal);
    }

    receive() external payable {}
}
