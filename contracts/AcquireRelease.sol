// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AcquireRelease {
    address public immutable operator;
    mapping(uint256 => bool) public settled;

    event Released(address indexed to, uint256 amount, uint256 nonce);

    constructor(address _operator) payable {
        operator = _operator;
    }

    modifier onlyOperator() {
        require(msg.sender == operator, "AcquireRelease: not operator");
        _;
    }

    function release(address payable to, uint256 amount, uint256 nonce)
        external onlyOperator
    {
        require(!settled[nonce], "AcquireRelease: already settled");
        require(address(this).balance >= amount, "AcquireRelease: insufficient funds");
        settled[nonce] = true;
        to.transfer(amount);
        emit Released(to, amount, nonce);
    }

    receive() external payable {}
}
