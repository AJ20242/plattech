import json
import os
from web3 import Web3


def _clean_hex(value: str, *, allow_0x: bool = True) -> str:
    value = (value or "").strip()
    if allow_0x and value.lower().startswith("0x"):
        value = value[2:]
    return value


def _is_hex(value: str) -> bool:
    if not value:
        return False
    return all(ch in "0123456789abcdefABCDEF" for ch in value)


class BlockchainAuditService:
    def __init__(self, rpc_url: str, contract_address: str, private_key: str):
        rpc_url = (rpc_url or "").strip()
        contract_address = (contract_address or "").strip()
        private_key = _clean_hex(private_key, allow_0x=True)

        if not rpc_url:
            raise ValueError("Missing Ganache RPC URL")

        if len(private_key) != 64 or not _is_hex(private_key):
            raise ValueError("Invalid private key format. Expected 64 hex characters.")

        if not Web3.is_address(contract_address):
            raise ValueError("Invalid contract address format.")

        self.w3 = Web3(Web3.HTTPProvider(rpc_url))

        if not self.w3.is_connected():
            raise RuntimeError("Cannot connect to Ganache RPC")

        self.private_key = "0x" + private_key
        self.account = self.w3.eth.account.from_key(self.private_key)
        self.address = self.account.address

        abi_path = os.path.join(os.path.dirname(__file__), "contract_abi.json")
        if not os.path.exists(abi_path):
            raise FileNotFoundError(f"ABI file not found: {abi_path}")

        with open(abi_path, "r", encoding="utf-8") as f:
            abi = json.load(f)

        self.contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=abi,
        )

    def _normalize_ticket_hash(self, ticket_hash: str) -> bytes:
        cleaned = _clean_hex(ticket_hash, allow_0x=True)
        if len(cleaned) != 64 or not _is_hex(cleaned):
            raise ValueError("ticket_hash must be a 64-character hex string")
        return Web3.to_bytes(hexstr="0x" + cleaned)

    def create_ticket_proof(self, ticket_id: str, ticket_hash: str):
        ticket_id = str(ticket_id or "").strip()
        if not ticket_id:
            raise ValueError("ticket_id is required")

        ticket_hash_bytes = self._normalize_ticket_hash(ticket_hash)
        nonce = self.w3.eth.get_transaction_count(self.address)

        tx = self.contract.functions.createTicketProof(
            ticket_id,
            ticket_hash_bytes,
        ).build_transaction(
            {
                "from": self.address,
                "nonce": nonce,
                "gas": 3000000,
                "gasPrice": self.w3.to_wei("20", "gwei"),
            }
        )

        signed_tx = self.w3.eth.account.sign_transaction(tx, self.private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        return {
            "txHash": tx_hash.hex(),
            "blockNumber": receipt.blockNumber,
        }

    def update_ticket_proof(self, ticket_id: str, ticket_hash: str):
        ticket_id = str(ticket_id or "").strip()
        if not ticket_id:
            raise ValueError("ticket_id is required")

        ticket_hash_bytes = self._normalize_ticket_hash(ticket_hash)
        nonce = self.w3.eth.get_transaction_count(self.address)

        tx = self.contract.functions.updateTicketProof(
            ticket_id,
            ticket_hash_bytes,
        ).build_transaction(
            {
                "from": self.address,
                "nonce": nonce,
                "gas": 3000000,
                "gasPrice": self.w3.to_wei("20", "gwei"),
            }
        )

        signed_tx = self.w3.eth.account.sign_transaction(tx, self.private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        return {
            "txHash": tx_hash.hex(),
            "blockNumber": receipt.blockNumber,
        }

    def get_ticket_proof(self, public_id: str):
        public_id = str(public_id or "").strip()
        if not public_id:
            raise ValueError("public_id is required")

        data = self.contract.functions.getTicketProof(public_id).call()

        return {
        "publicId": data[0],
        "ticketHash": data[1].hex(),
        "createdAt": int(data[2]),
        "updatedAt": int(data[3]),
        "exists": bool(data[4]),
    }