// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract ChainSignatures {
    // Generator point G of secp256k1
    uint256 constant Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 constant Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    struct SignatureRequest {
        uint256 payload;
        address requester;
        string path;
    }

    struct SignatureResponse {
        PublicKey big_r;
        uint256 s;
        uint8 recovery_id;
    }

    // public key in affine form
    struct PublicKey {
        uint256 x;
        uint256 y;
    }

    uint256 public threshold;
    mapping(bytes32 => SignatureRequest) public pendingRequests;
    uint256 public requestCounter;
    PublicKey public publicKey;

    mapping(bytes32 => uint256) public depositToRefund;

    event SignatureRequested(bytes32 indexed requestId, address requester, uint256 payload, string path);
    event SignatureResponded(bytes32 indexed requestId, bytes32 big_r, bytes32 s, uint8 recovery_id);

    constructor(PublicKey memory _publicKey) {
        publicKey = _publicKey;
    }

    function getPublicKey() public view returns (PublicKey memory) {
        return publicKey;
    }

    function derivedPublicKey(string memory path, address _predecessor) public view returns (PublicKey memory) {
        address predecessor = _predecessor == address(0) ? msg.sender : _predecessor;
        uint256 epsilon = deriveEpsilon(path, predecessor);
        PublicKey memory _derivedPublicKey = deriveKey(publicKey, epsilon);
        return _derivedPublicKey;
    }

function deriveKey(PublicKey memory _publicKey, uint256 epsilon) internal view returns (PublicKey memory) {
        
        // G * epsilon + publicKey
        (uint256 epsilonGx, uint256 epsilonGy) = ecMul(epsilon, gx, gy);
        (uint256 resultX, uint256 resultY) = ecAdd(epsilonGx, epsilonGy, _publicKey.x, _publicKey.y);
        return PublicKey(resultX, resultY, 0);
    }

    function deriveEpsilon(string memory path, address predecessor) public pure returns (uint256) {
        // TODO Ethereum doesn't have SHA3-256, so we use keccak256 temporarily
        bytes32 epsilonBytes = keccak256(abi.encodePacked("near-mpc-recovery v0.1.0 epsilon derivation:", predecessor, ",", path));
        uint256 epsilon = uint256(epsilonBytes);
        return epsilon;
    }

    function sign(bytes32 _payload, string memory _path) external payable returns (bytes32) {
        uint256 requiredDeposit = getSignatureDeposit();
        require(msg.value >= requiredDeposit, "Insufficient deposit");

        // Concert payload to int as big-endian, check if payload is than the secp256k1 curve order
        uint256 payload = uint256(_payload);
        require(
            payload < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
            "Payload exceeds secp256k1 curve order"
        );

        bytes32 requestId = keccak256(abi.encodePacked(payload, msg.sender, _path));
        require(pendingRequests[requestId].requester == address(0), "Request already exists");

        SignatureRequest memory request = SignatureRequest(payload, msg.sender, _path);
        pendingRequests[requestId] = request;
        depositToRefund[requestId] = msg.value - requiredDeposit;
        requestCounter++;

        emit SignatureRequested(requestId, msg.sender, payload, _path);

        return requestId;
    }
    
    function respond(bytes32 _requestId, SignatureResponse memory _response) external {        
        SignatureRequest storage request = pendingRequests[_requestId];
        require(request.requester != address(0), "Request not found");

        uint256 epsilon = deriveEpsilon(request.path, request.requester);
        PublicKey memory expectedPublicKey = deriveKey(publicKey, epsilon);

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

    function checkECSignature(
        PublicKey memory _expectedPk,
        PublicKey memory _bigR,
        uint256 _s,
        bytes32 _msgHash,
        uint8 _recoveryId
    ) internal pure returns (bool) {
        // Reconstruct the signature
        bytes32 r = bytes32(_bigR);
        bytes32 s = bytes32(_s);
    
        // Recover the signer's address
        // TODO ethereum ecrecover returns an address, but we need a curve point
        PublicKey foundPk = ecrecover(_msgHash, _recoveryId, r, s);
        
        // If recovery fails with the given recovery ID, try the alternative
        uint8 alternativeRecoveryId = _recoveryId ^ 1;
        address alternativeRecoveredAddress = ecrecover(_msgHash, alternativeRecoveryId, r, s);
        
        if (alternativeRecoveredAddress == _expectedPk) {
            return true;
        }
        
        // If both recovery attempts fail, return false
        return false;
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
