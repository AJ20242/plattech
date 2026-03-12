// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TicketRegistry {
    enum TicketStatus {
        Open,
        InProgress,
        Resolved,
        Closed
    }

    struct Ticket {
        uint256 id;
        string publicId;
        string ownerEmail;
        string subject;
        string description;
        string priority;
        TicketStatus status;
        uint256 createdAt;
        uint256 updatedAt;
        address createdBy;
        bool exists;
    }

    uint256 private nextTicketId = 1;
    address public admin;

    mapping(uint256 => Ticket) private tickets;
    mapping(string => uint256) private publicIdToId;

    event TicketCreated(
        uint256 indexed id,
        string publicId,
        string ownerEmail,
        string subject,
        string priority,
        uint256 createdAt,
        address indexed createdBy
    );

    event TicketStatusUpdated(
        uint256 indexed id,
        string publicId,
        TicketStatus oldStatus,
        TicketStatus newStatus,
        uint256 updatedAt,
        address indexed updatedBy
    );

    event TicketClosed(
        uint256 indexed id,
        string publicId,
        uint256 updatedAt,
        address indexed closedBy
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }

    modifier ticketMustExist(uint256 ticketId) {
        require(tickets[ticketId].exists, "Ticket does not exist");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function createTicket(
        string memory _publicId,
        string memory _ownerEmail,
        string memory _subject,
        string memory _description,
        string memory _priority
    ) public returns (uint256) {
        require(bytes(_publicId).length > 0, "Public ID is required");
        require(bytes(_ownerEmail).length > 0, "Owner email is required");
        require(bytes(_subject).length > 0, "Subject is required");
        require(publicIdToId[_publicId] == 0, "Public ID already exists");

        uint256 ticketId = nextTicketId;

        tickets[ticketId] = Ticket({
            id: ticketId,
            publicId: _publicId,
            ownerEmail: _ownerEmail,
            subject: _subject,
            description: _description,
            priority: _priority,
            status: TicketStatus.Open,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            createdBy: msg.sender,
            exists: true
        });

        publicIdToId[_publicId] = ticketId;
        nextTicketId++;

        emit TicketCreated(
            ticketId,
            _publicId,
            _ownerEmail,
            _subject,
            _priority,
            block.timestamp,
            msg.sender
        );

        return ticketId;
    }

    function updateTicketStatus(
        uint256 ticketId,
        TicketStatus newStatus
    ) public onlyAdmin ticketMustExist(ticketId) {
        Ticket storage t = tickets[ticketId];
        TicketStatus oldStatus = t.status;

        t.status = newStatus;
        t.updatedAt = block.timestamp;

        emit TicketStatusUpdated(
            ticketId,
            t.publicId,
            oldStatus,
            newStatus,
            block.timestamp,
            msg.sender
        );
    }

    function closeTicket(uint256 ticketId)
        public
        onlyAdmin
        ticketMustExist(ticketId)
    {
        Ticket storage t = tickets[ticketId];
        t.status = TicketStatus.Closed;
        t.updatedAt = block.timestamp;

        emit TicketClosed(ticketId, t.publicId, block.timestamp, msg.sender);
    }

    function getTicket(uint256 ticketId)
        public
        view
        ticketMustExist(ticketId)
        returns (
            uint256 id,
            string memory publicId,
            string memory ownerEmail,
            string memory subject,
            string memory description,
            string memory priority,
            TicketStatus status,
            uint256 createdAt,
            uint256 updatedAt,
            address createdBy
        )
    {
        Ticket memory t = tickets[ticketId];
        return (
            t.id,
            t.publicId,
            t.ownerEmail,
            t.subject,
            t.description,
            t.priority,
            t.status,
            t.createdAt,
            t.updatedAt,
            t.createdBy
        );
    }

    function getTicketIdByPublicId(string memory _publicId)
        public
        view
        returns (uint256)
    {
        return publicIdToId[_publicId];
    }

    function totalTickets() public view returns (uint256) {
        return nextTicketId - 1;
    }
}