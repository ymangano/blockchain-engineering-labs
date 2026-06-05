from chain.block import BlockHeader, Block, compute_txs_hash
from chain.transaction import Transaction
from chain.blockchain import Blockchain
from chain.mempool import Mempool
from config import BLOCK_DIFFICULTY, HASH_SIZE
import time as time_module
import threading


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

    def __init__(self, blockchain: Blockchain):
        self.blockchain: Blockchain = blockchain
        self.mempool: Mempool = self.blockchain.mempool

        self.stop_event = threading.Event()

    def mine_block(self) -> Block | None:
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
            if self.stop_event.is_set():
                print("Mining stopped due to new block arrival.\n")
                return None

            header.nonce = nonce

            block = Block(
                header=header,
                transactions=transactions,
            )

            if block.validate():
                self.blockchain.append_block(block)
                return block

            nonce += 1


class MinerThread:

    def __init__(self, miner: Miner, interval: int):
        self.miner = miner
        self.interval = interval

    def run(self):
        while True:

            time_module.sleep(self.interval)

            self.miner.stop_event.clear()

            block = self.miner.mine_block()

            if block:
                print("Mined:", block.header.block_hash().hex())
                self.miner.blockchain.print_chain()

            
