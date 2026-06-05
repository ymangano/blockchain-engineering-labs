from dataclasses import dataclass
from chain.crypto import sha256, u64_be
from ipv8.keyvault.crypto import ECCrypto


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

    def valid_signature(self) -> bool:
        """
        Verify the server transaction signature.

        Signature message:
            sender_key  data  timestamp_8byte_be
        """
        try:
            crypto = ECCrypto()
            public_key = crypto.key_from_public_bin(self.sender_key)
            signed_data = self.sender_key + self.data + u64_be(self.timestamp)

            return crypto.is_valid_signature(
                public_key,
                signed_data,
                self.signature,
            )
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False
