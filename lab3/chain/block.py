from chain.crypto import sha256, u64_be, u32_be
from chain.transaction import Transaction
from dataclasses import dataclass
from chain.pow import valid_pow
from config import HASH_SIZE, HEADER_SIZE

"""
Naming:
transactions  -> list[Transaction]
tx_hashes     -> list[bytes]
txs_hash      -> single bytes commitment -> sha256(tx1 + tx2 + ... + txn)
"""


def compute_txs_hash(tx_hashes: list[bytes]) -> bytes:
    """
    Compute the block body commitment.

    The lab requires:

        txs_hash = SHA256(tx_hash_1 || tx_hash_2 || ... || tx_hash_n)

    For an empty block:

        txs_hash = SHA256(b"")

    Since b"".join([]) is b"", this works for both normal and empty blocks.
    """

    if len(tx_hashes) == 0:
        return sha256(b"")

    return sha256(b"".join(tx_hashes))


@dataclass
class BlockHeader:
    """
    Block header format.

    The packed header must be exactly 84 bytes:

        prev_hash   32 bytes
        txs_hash    32 bytes
        timestamp    8 bytes, uint64 big-endian
        difficulty   4 bytes, uint32 big-endian
        nonce        8 bytes, uint64 big-endian
    """

    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int

    def pack(self) -> bytes:
        """
        Pack the block header into its exact binary format.
        """
        assert len(self.prev_hash) == HASH_SIZE
        assert len(self.txs_hash) == HASH_SIZE

        return (
            self.prev_hash
            + self.txs_hash
            + u64_be(self.timestamp)
            + u32_be(self.difficulty)
            + u64_be(self.nonce)
        )

    def block_hash(self) -> bytes:
        """
        Compute the 32-byte hash of this block header and check that the packed header is the correct length.
        """
        packed = self.pack()

        assert len(packed) == HEADER_SIZE

        return sha256(packed)


@dataclass
class Block:
    """
    A block consists of:
    - a header
    - the transactions included in the block

    Internally we keep full Transaction objects because that makes validation easy.
    When responding to the server, we only send concatenated transaction hashes.
    """

    header: BlockHeader
    transactions: list[Transaction]

    def validate(self) -> bool:
        """
        Validate this block by checking:
        - prev_hash has correct size
        - txs_hash has correct size
        - txs_hash matches the included transactions
        - block hash satisfies declared PoW difficulty

        This does NOT check whether the block links to a previous block.
        Chain-link validation should be done when appending to the chain.
        """
        assert len(self.header.prev_hash) == HASH_SIZE
        assert len(self.header.txs_hash) == HASH_SIZE

        tx_hashes = [tx.tx_hash() for tx in self.transactions]

        expected_txs_hash = compute_txs_hash(tx_hashes)

        if expected_txs_hash != self.header.txs_hash:
            return False

        block_hash = self.header.block_hash()

        if not valid_pow(block_hash, self.header.difficulty):
            return False

        return True


def create_genesis_block() -> Block:
    """
    Create the fixed genesis block.

    All 3 teammates must create EXACTLY the same genesis block.
    Otherwise your chains already disagree at height 0.

    We use:
    - prev_hash = 32 zero bytes
    - no transactions
    - txs_hash = SHA256(b"")
    - timestamp = 0
    - difficulty = 0
    - nonce = 0

    difficulty = 0 means the genesis block is always valid.
    """
    header = BlockHeader(
        prev_hash=b"\x00" * HASH_SIZE,
        txs_hash=compute_txs_hash([]),
        timestamp=0,
        difficulty=0,
        nonce=0,
    )

    return Block(
        header=header,
        transactions=[],
    )
