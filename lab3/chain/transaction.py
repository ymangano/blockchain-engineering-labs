from dataclasses import dataclass
from chain.crypto import sha256, u64_be


@dataclass
class Transaction:
    """
    A transaction received from the Lab 3 server.

    The transaction hash must be:
        SHA256(sender_key || data || timestamp_8byte_be || signature)
    """

    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes

    def tx_hash(self) -> bytes:
        """
        Compute the 32-byte transaction hash.
        """
        blob = self.sender_key + self.data + u64_be(self.timestamp) + self.signature

        return sha256(blob)
