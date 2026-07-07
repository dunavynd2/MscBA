// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BridgeMainnet {
    address public authorizedRelayer;
    mapping(uint256 => bool) public processedNonces;

    event SettlementExecuted(address indexed target, uint256 assetAmount);

    constructor(address _authorizedRelayer) {
        authorizedRelayer = _authorizedRelayer;
    }

    function releaseMainnetFunds(
        address target,
        uint256 amount,
        uint256 nonce,
        bytes memory cryptographicSignature
    ) external {
        require(!processedNonces[nonce], "Transaction sequence already cleared");

        bytes32 internalMessageHash = keccak256(abi.encodePacked(target, amount, nonce));
        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", internalMessageHash)
        );

        address verifiedSigner = recoverSigner(ethSignedMessageHash, cryptographicSignature);
        require(verifiedSigner == authorizedRelayer, "Invalid cryptographic sender verification");

        processedNonces[nonce] = true;
        payable(target).transfer(amount);

        emit SettlementExecuted(target, amount);
    }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _sig)
        internal
        pure
        returns (address)
    {
        require(_sig.length == 65, "Malformed signature payload");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(_sig, 32))
            s := mload(add(_sig, 64))
            v := byte(0, mload(add(_sig, 96)))
        }
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    receive() external payable {}
}
