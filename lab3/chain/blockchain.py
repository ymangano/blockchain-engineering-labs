import threading

from chain.block import Block, create_genesis_block, BlockHeader
from chain.mempool import Mempool
from chain.transaction import Transaction


class Blockchain:
    """
    Holds the local blockchain state for one node.

    This class is responsible for:
    - storing the chain
    - storing the mempool
    - appending valid blocks
    - exposing height/tip/block helpers
    """

    def __init__(self):
        # Chain starts with the fixed genesis block at height 0.
        self.chain: list[Block] = [create_genesis_block()]

        self.mempool: Mempool = Mempool()
        self.lock = threading.Lock()

    # -------------------------------------------------------------------------
    # Basic chain info
    # -------------------------------------------------------------------------

    def height(self) -> int:
        """
        Return current chain height.

        Genesis block has height 0.
        """
        with self.lock:
            return len(self.chain) - 1

    def tip(self) -> Block:
        """
        Return latest block.
        """
        return self.chain[-1]

    def previous_hash(self) -> bytes:
        """
        Return hash of latest block.
        """
        with self.lock:
            return self.tip().header.block_hash()

    def get_block(self, height: int) -> Block | None:
        """
        Return block at height, or None if height is invalid.
        """
        with self.lock:
            if height < 0 or height >= len(self.chain):
                return None

            return self.chain[height]

    # -------------------------------------------------------------------------
    # Block validation / appending
    # -------------------------------------------------------------------------

    def block_links_to_previous(self, block: Block, previous_block: Block) -> bool:
        """
        Check whether block correctly points to previous_block.
        """
        return block.header.prev_hash == previous_block.header.block_hash()

    def can_append_block(self, block: Block) -> bool:
        """
        Check whether a block can be appended to the current chain tip.

        This checks:
        - the block itself is valid
        - the block's prev_hash matches the current tip hash
        """
        if not block.validate():
            return False

        return self.block_links_to_previous(block, self.tip())

    def append_block(self, block: Block) -> bool:
        """
        Append block to the chain if it validly extends the current tip.

        Returns:
            True if appended
            False otherwise
        """
        with self.lock:
            if not self.can_append_block(block):
                return False

            self.chain.append(block)

        # Remove included transactions from mempool, if we had them.
        self.mempool.remove_multiple_transactions(block.transactions)

        return True

    def print_chain(self) -> None:
        """
        Pretty-print the entire blockchain.
        """
        print("\n========== BLOCKCHAIN ==========")

        for height, block in enumerate(self.chain):
            header = block.header

            print(f"\n----- Block {height} -----")
            print(f"Hash       : {header.block_hash().hex()}")
            print(f"Prev Hash  : {header.prev_hash.hex()}")
            print(f"Txs Hash   : {header.txs_hash.hex()}")
            print(f"Timestamp  : {header.timestamp}")
            print(f"Difficulty : {header.difficulty}")
            print(f"Nonce      : {header.nonce}")
            print(f"Tx Count   : {len(block.transactions)}")

            for tx_index, tx in enumerate(block.transactions):
                print(f"  TX {tx_index}: " f"{tx.tx_hash().hex()}")

        print("\n===============================\n")
