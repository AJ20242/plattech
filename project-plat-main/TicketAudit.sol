// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract TicketAudit {
    address public admin;

    struct TicketProof {
        string publicId;
        bytes32 ticketHash;
        uint256 createdAt;
        uint256 updatedAt;
        bool exists;
    }

    mapping(string => TicketProof) private proofs;

    event TicketProofCreated(
        string publicId,
        bytes32 ticketHash,
        uint256 createdAt,
        address indexed createdBy
    );

    event TicketProofUpdated(
        string publicId,
        bytes32 oldHash,
        bytes32 newHash,
        uint256 updatedAt,
        address indexed updatedBy
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function createTicketProof(
        string memory _publicId,
        bytes32 _ticketHash
    ) public returns (bool) {
        require(bytes(_publicId).length > 0, "Public ID required");
        require(!proofs[_publicId].exists, "Proof already exists");

        proofs[_publicId] = TicketProof({
            publicId: _publicId,
            ticketHash: _ticketHash,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            exists: true
        });

        emit TicketProofCreated(_publicId, _ticketHash, block.timestamp, msg.sender);
        return true;
    }

    function updateTicketProof(
        string memory _publicId,
        bytes32 _newHash
    ) public onlyAdmin returns (bool) {
        require(proofs[_publicId].exists, "Proof does not exist");

        bytes32 oldHash = proofs[_publicId].ticketHash;
        proofs[_publicId].ticketHash = _newHash;
        proofs[_publicId].updatedAt = block.timestamp;

        emit TicketProofUpdated(_publicId, oldHash, _newHash, block.timestamp, msg.sender);
        return true;
    }

    function getTicketProof(string memory _publicId)
        public
        view
        returns (
            string memory publicId,
            bytes32 ticketHash,
            uint256 createdAt,
            uint256 updatedAt,
            bool exists
        )
    {
        TicketProof memory p = proofs[_publicId];
        return (p.publicId, p.ticketHash, p.createdAt, p.updatedAt, p.exists);
    }
}