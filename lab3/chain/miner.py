from chain.block import BlockHeader, Block, compute_txs_hash
from chain.transaction import Transaction
from chain.blockchain import Blockchain
from chain.mempool import Mempool
from config import BLOCK_DIFFICULTY, HASH_SIZE
import time as time_module

class Miner:
    """
    Miner is responsible for mining new blocks.

    Mining means:
    - choose the transactions for the block
    - compute txs_hash
    - build a block header pointing to prev_hash
    - try nonce values until the block hash satisfies the difficulty

    This class only has one method, mine_block, which returns a full valid Block.
    """

    def __init__(self, blockchain: Blockchain, mempool: Mempool):
        self.blockchain: Blockchain = blockchain
        self.mempool: Mempool = mempool

    async def mine_block(self) -> Block:
        """
        Mine a new block.

        Mining means:
        - choose the transactions for the block
        - compute txs_hash
        - build a block header pointing to prev_hash
        - try nonce values until the block hash satisfies the difficulty

        This function returns a full valid Block.
        """
        prev_hash: bytes = self.blockchain.previous_hash()
        transactions = self.mempool.get_transactions()
        difficulty = BLOCK_DIFFICULTY
        timestamp = int(time_module.time())

        assert len(prev_hash) == HASH_SIZE

        tx_hashes = [tx.tx_hash() for tx in transactions]
        txs_hash = compute_txs_hash(tx_hashes)

        nonce = 0

        header = BlockHeader(
            prev_hash=prev_hash,
            txs_hash=txs_hash,
            timestamp=timestamp,
            difficulty=difficulty,
            nonce=nonce,
        )

        while True:
            header.nonce = nonce

            block = Block(
                header=header,
                transactions=transactions,
            )

            if block.validate():
                self.blockchain.append_block(block)
                return block

            nonce += 1
