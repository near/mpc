// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract ChainSignatures is Ownable {
    using ECDSA for bytes32;

    struct Participant {
        string url;
        bytes32 cipherPk;
        address signPk;
    }

    struct SignatureRequest {
        bytes32 payloadHash;
        address requester;
        string path;
    }

    struct SignatureResponse {
        bytes32 big_r;
        bytes32 s;
        uint8 recovery_id;
    }

    uint256 public threshold;
    mapping(bytes32 => SignatureRequest) public pendingRequests;
    uint256 public requestCounter;
    address public publicKey;

    mapping(bytes32 => uint256) public depositToRefund;

    event SignatureRequested(bytes32 indexed requestId, address requester, bytes32 payloadHash, string path);
    event SignatureResponded(bytes32 indexed requestId, bytes32 big_r, bytes32 s, uint8 recovery_id);

    constructor(address _publicKey) {
        publicKey = _publicKey;
    }

    function sign(bytes32 _payloadHash, string memory _path) external payable returns (bytes32) {
        uint256 requiredDeposit = getSignatureDeposit();
        require(msg.value >= requiredDeposit, "Insufficient deposit");

        bytes32 requestId = keccak256(abi.encodePacked(_payloadHash, msg.sender, _path));
        require(pendingRequests[requestId].requester == address(0), "Request already exists");

        pendingRequests[requestId] = SignatureRequest(_payloadHash, msg.sender, _path);
        depositToRefund[requestId] = msg.value - requiredDeposit;
        requestCounter++;

        emit SignatureRequested(requestId, msg.sender, _payloadHash, _path);

        return requestId;
    }
    function respond(bytes32 _requestId, SignatureResponse memory _response) external {        
        SignatureRequest storage request = pendingRequests[_requestId];
        require(request.requester != address(0), "Request not found");

        // Verify the signature
        // Derive the expected public key
        bytes32 epsilon = keccak256(abi.encodePacked("near-mpc-recovery v0.1.0 epsilon derivation:", request.requester, ",", request.path));
        address expectedPublicKey = deriveKey(publicKey, epsilon);

        // Check the signature
        require(
            checkECSignature(
                expectedPublicKey,
                uint256(_response.big_r),
                uint256(_response.s),
                request.payloadHash,
                _response.recovery_id
            ),
            "Invalid signature"
        );

        emit SignatureResponded(_requestId, _response.big_r, _response.s, _response.recovery_id);

        // Refund excess deposit
        uint256 refund = depositToRefund[_requestId];

        // Clean up
        delete pendingRequests[_requestId];
        delete depositToRefund[_requestId];
        requestCounter--;

        if (refund > 0) {
            payable(request.requester).transfer(refund);
        }
    }

    function getSignatureDeposit() public view returns (uint256) {
        // Simplified deposit calculation
        if (requestCounter <= 3) {
            return 1 wei;
        } else {
            return (requestCounter - 3) * 4 * 1e15; // 0.004 ETH (~1 USD) first request after the first 3
        }
    }

    function deriveKey(address _publicKey, bytes32 _epsilon) internal view returns (address) {
        // Convert public key to (x, y) coordinates
        (uint256 x, uint256 y) = abi.decode(abi.encodePacked(_publicKey), (uint256, uint256));
        
        // Perform elliptic curve point addition
        // G * epsilon + publicKey
        (x, y) = ecMul(uint256(_epsilon), 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8);
        (x, y) = ecAdd(x, y, uint256(uint160(_publicKey)), y);
        
        // Convert result back to address
        return address(uint160(uint256(keccak256(abi.encodePacked(x, y)))));
    }

    function checkECSignature(
        address _expectedPk,
        uint256 _bigR,
        uint256 _s,
        bytes32 _msgHash,
        uint8 _recoveryId
    ) internal pure returns (bool) {
        // TODO
    }

    // Helper function for elliptic curve point multiplication
    function ecMul(uint256 _k, uint256 _x, uint256 _y) internal view returns (uint256, uint256) {
        (bool success, bytes memory result) = address(0x07).staticcall(abi.encode(_k, _x, _y));
        require(success, "EC multiplication failed");
        return abi.decode(result, (uint256, uint256));
    }

    // Helper function for elliptic curve point addition
    function ecAdd(uint256 _x1, uint256 _y1, uint256 _x2, uint256 _y2) internal view returns (uint256, uint256) {
        (bool success, bytes memory result) = address(0x06).staticcall(abi.encode(_x1, _y1, _x2, _y2));
        require(success, "EC addition failed");
        return abi.decode(result, (uint256, uint256));
    }

}
