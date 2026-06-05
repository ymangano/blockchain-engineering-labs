from chain.block import Block, create_genesis_block
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

    # -------------------------------------------------------------------------
    # Basic chain info
    # -------------------------------------------------------------------------

    def height(self) -> int:
        """
        Return current chain height.

        Genesis block has height 0.
        """
        return len(self.chain) - 1

    def tip(self) -> Block:
        """
        Return latest block.
        """
        return self.chain[-1]

    # def tip_hash(self) -> bytes:
    #     """
    #     Return hash of latest block.
    #     """
    #     return self.tip().block.hash()

    def get_block(self, height: int) -> Block | None:
        """
        Return block at height, or None if height is invalid.
        """
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
        if not self.can_append_block(block):
            return False

        self.chain.append(block)

        # Remove included transactions from mempool, if we had them.
        self.mempool.remove_multiple_transactions(block.transactions)

        return True
